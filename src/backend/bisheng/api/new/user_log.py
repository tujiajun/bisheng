from bisheng.database.models.audit_log import AuditLog, SystemId, EventType, ObjectType, AuditLogDao
from bisheng.database.models.user import UserDao
from bisheng.database.models.user_group import UserGroupDao


class LogService:
    @classmethod
    def log_user_batch_created(cls,
                               created_user_id: int,
                               created_user_name: str,
                               ip_address: str = "",
                               operator_id: int = 1):
        """
        批量注册：对“每个创建成功的用户”写一条审计日志。
        """
        # 操作者：平台管理员（ID=1），用户名实时查库
        operator = UserDao.get_user(operator_id)
        operator_name = operator.user_name

        # 被创建用户的分组ID列表（已在批量注册里把用户加入默认组后再调用此方法）
        group_ids = [g.group_id for g in UserGroupDao.get_user_group(created_user_id)]

        audit = AuditLog(
            operator_id=operator_id,
            operator_name=operator_name,
            group_ids=group_ids,
            system_id=SystemId.SYSTEM.value,
            event_type=EventType.UPDATE_USER.value,
            object_type=ObjectType.USER_CONF.value,
            object_id=str(created_user_id),  # 批量注册用户的用户ID
            object_name=created_user_name,  # 批量注册用户的用户名
            note="批量注册",  # 备注：批量注册
            ip_address=ip_address or "",
        )
        AuditLogDao.insert_audit_logs([audit])

    @classmethod
    def sso_login(cls, user_name: str, ip_address: str):
        db_user = UserDao.get_user_by_username(user_name)
        # 获取用户所属的分组
        user_group = UserGroupDao.get_user_group(db_user.user_id)
        user_group = [one.group_id for one in user_group]
        audit_log = AuditLog(
            operator_id=db_user.user_id,
            operator_name=db_user.user_name,
            group_ids=user_group,
            system_id=SystemId.SYSTEM.value,
            event_type=EventType.USER_LOGIN.value,
            object_type=ObjectType.NONE.value,
            object_id='',
            object_name='',
            ip_address=ip_address,
            note='SSO登录',
        )
        AuditLogDao.insert_audit_logs([audit_log])