from base64 import b64encode
from typing import List, Dict, Any
import rsa  # 与解密侧保持同库
from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field
from bisheng.database.base import session_getter
from bisheng.api.services.user_service import UserService, UserPayload
from bisheng.api.v1.schemas import CreateUserReq, GroupAndRoles
from bisheng.api.v1.schemas import resp_200
from bisheng.cache.redis import redis_client
from bisheng.database.models.user import UserDao, UserRead
from bisheng.utils.constants import RSA_KEY
from bisheng.api.new.get_username import GetUserNamefromToken  # 从E系统token中解析用户名
from bisheng.api.new.user_log import LogService
from bisheng.database.models.user import User
from bisheng.api.services.role_group_service import RoleGroupService
from bisheng.database.models.role import RoleDao
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi_jwt_auth import AuthJWT
from bisheng.api.JWT import ACCESS_TOKEN_EXPIRE_TIME
from bisheng.api.services.user_service import (gen_user_jwt)
from bisheng.utils.constants import USER_CURRENT_SESSION

router = APIRouter()

SYSTEM_DEFAULT_PASSWORD = "ChangeMe123!" # 工作流平台批量注册时的默认密码
WORKSHOP_NAME = "dszhcj" # 大生智慧车间域名

class BatchCreateWithGroupReq(BaseModel):
    """仅一个组 + 该组内一个(多个)角色"""
    usernames: List[str] = Field(..., description="待注册用户名列表")
    group_id: int = Field(..., description="用户组ID")
    role_ids: List[int] = Field(..., description="该组内的多个角色ID")

@router.post("/batch_create", status_code=200)
async def batch_create_with_group(req: BatchCreateWithGroupReq, request: Request):
    # 1) 企业 token
    header_auth = request.headers.get("Authorization")
    if not header_auth:
        raise HTTPException(status_code=401, detail="缺少 Authorization")

    token = _extract_bearer_token(header_auth)
    if not token:
        raise HTTPException(status_code=401, detail="无效 Authorization")

    # 2) 企业身份认证（仅允许企业侧 api 账号）
    caller_name = await GetUserNamefromToken(token, WORKSHOP_NAME)
    if caller_name != "api":
        raise HTTPException(status_code=403, detail="无权限批量注册")

    # 3) 基本参数校验
    if not req.usernames:
        raise HTTPException(status_code=400, detail="usernames 不能为空")
    if not req.role_ids:
        raise HTTPException(status_code=400, detail="role_ids 不能为空")

    # 【可选】校验“角色必须属于该组”

    # 4) 获取系统超级管理员上下文（id=1，role='admin'，user_name 从 DB）
    admin_record = UserDao.get_user(1)
    system_admin = UserPayload(
        user_id=1,
        role='admin',
        user_name=admin_record.user_name
    )

    # 5) 准备密码传参（兼容 decrypt_md5_password）
    #    若 Redis 有 RSA_KEY：需用公钥加密 + Base64；否则传明文
    rsa_entry = redis_client.get(RSA_KEY)
    if rsa_entry:
        try:
            public_key = rsa_entry[0]          # 解密取的是 value[1] -> 私钥，这里取 value[0] -> 公钥
            encrypted = rsa.encrypt(SYSTEM_DEFAULT_PASSWORD.encode("utf-8"), public_key)
            password_for_create = b64encode(encrypted).decode("utf-8")
        except Exception:
            # 兜底：若加密失败，退回明文（与 decrypt 约定不一致时，create_user 会报错）
            password_for_create = SYSTEM_DEFAULT_PASSWORD
    else:
        password_for_create = SYSTEM_DEFAULT_PASSWORD

    created: List[str] = []
    skipped: List[Dict[str, Any]] = []

    # 6) 用户创建：先用现有接口注册（启用态），随后置禁用
    for name in req.usernames:
        # 6.1 长度限制
        if len(name) > 30:
            skipped.append({"user_name": name, "reason": f"用户名最长30个字符"})
            continue

        try:
            # 6.2 并发兜底查重
            if UserDao.get_user_by_username(name):
                skipped.append({"user_name": name, "reason": "用户名已存在"})
                continue

            # 6.3 构造与 create_user 一致的入参（仅一个组 + 多角色）
            create_req = CreateUserReq(
                user_name=name,
                password=password_for_create,
                group_roles=[GroupAndRoles(group_id=req.group_id, role_ids=req.role_ids)]
            )

            # 6.4 复用业务逻辑（此时用户为启用态）
            new_user = UserService.create_user(
                request=request,
                login_user=system_admin,
                req_data=create_req
            )

            # 6.5 置为禁用（delete=1），并持久化
            _disable_user_by_id(new_user.user_id)

            # 6.6 审计日志
            LogService.log_user_batch_created(
                created_user_id=new_user.user_id,
                created_user_name=new_user.user_name,
                ip_address=(request.client.host if request.client else "")
            )

            created.append(name)

        except Exception as e:
            skipped.append({"user_name": name, "reason": f"创建或禁用失败: {str(e)}"})

    data = {
        "created_usernames": created,
        "created_count": len(created),
        "skipped": skipped,
        "skipped_count": len(skipped),
        "group_id": req.group_id,
        "role_ids": req.role_ids,
        "default_password_hint": "账号已创建且默认禁用（需在平台启用）；初始密码为系统默认密码。"
    }
    return resp_200(data)

@router.get("/get_groups", status_code=200)
async def get_all_group(request: Request):
    """
    获取所有分组
    """
    # 1) 企业 token
    header_auth = request.headers.get("Authorization")
    if not header_auth:
        raise HTTPException(status_code=401, detail="缺少 Authorization")

    token = _extract_bearer_token(header_auth)
    if not token:
        raise HTTPException(status_code=401, detail="无效 Authorization")

    # 2) 企业身份认证（仅允许企业侧 api 账号）
    caller_name = await GetUserNamefromToken(token, WORKSHOP_NAME)
    if caller_name != "api":
        raise HTTPException(status_code=403, detail="无权限查看")

    groups_res = RoleGroupService().get_group_list([])
    return resp_200({'records': groups_res})

@router.get("/get_roles", status_code=200)
async def get_group_roles(request: Request,
                          group_id: List[int] = Query(..., description="用户组ID列表")):
    """
    获取用户组内的角色列表
    """
    # 1) 企业 token
    header_auth = request.headers.get("Authorization")
    if not header_auth:
        raise HTTPException(status_code=401, detail="缺少 Authorization")

    token = _extract_bearer_token(header_auth)
    if not token:
        raise HTTPException(status_code=401, detail="无效 Authorization")

    # 2) 企业身份认证（仅允许企业侧 api 账号）
    caller_name = await GetUserNamefromToken(token, WORKSHOP_NAME)
    if caller_name != "api":
        raise HTTPException(status_code=403, detail="无权限查看")

    # 3) 查询组下角色列表
    role_list = RoleDao.get_role_by_groups(group_id, keyword = None, page=0, limit=0)
    total = RoleDao.count_role_by_groups(group_id, keyword = None)

    return resp_200(data={
        "data": role_list,
        "total": total
    })

@router.post('/sso_login')
async def sso_login(*, request: Request, Authorize: AuthJWT = Depends()):
    # 1) 企业 token
    header_auth = request.headers.get("Authorization")
    if not header_auth:
        raise HTTPException(status_code=401, detail="缺少 Authorization")

    token = _extract_bearer_token(header_auth)
    if not token:
        raise HTTPException(status_code=401, detail="无效 Authorization")

    # 2) 企业身份认证
    enp_username = await GetUserNamefromToken(token, WORKSHOP_NAME)
    db_user = UserDao.get_user_by_username(enp_username)

    if not db_user:
        raise HTTPException(status_code=403, detail='该账号不存在，请联系管理员注册')

    if 1 == db_user.delete:
        raise HTTPException(status_code=403, detail='该账号已被禁用，请联系管理员启用')

    access_token, refresh_token, role, web_menu = gen_user_jwt(db_user)

    # Set the JWT cookies in the response
    Authorize.set_access_cookies(access_token)
    Authorize.set_refresh_cookies(refresh_token)

    # 设置登录用户当前的cookie, 比jwt有效期多一个小时
    redis_client.set(USER_CURRENT_SESSION.format(db_user.user_id), access_token, ACCESS_TOKEN_EXPIRE_TIME + 3600)

    # 记录审计日志
    LogService.sso_login(user_name= db_user.user_name,
                         ip_address=(request.client.host if request.client else "")
                         )

    return resp_200(UserRead(role=str(role), web_menu=web_menu, access_token=access_token,
                             **db_user.__dict__))

def _extract_bearer_token(header_val: str) -> str:
    if not header_val:
        return ""
    hv = header_val.strip()
    if hv.lower().startswith("bearer "):
        return hv[7:].strip()
    return hv  # 已是裸 token 的情况

def _disable_user_by_id(user_id: int) -> None:
    with session_getter() as session:
        user = session.get(User, user_id)   # SELECT ... WHERE pk = user_id
        if not user:
            return
        if getattr(user, "delete", 0) == 1:
            return
        user.delete = 1  # 0=启用，1=禁用
        session.add(user)
        session.commit()

