import httpx
from fastapi import HTTPException

async def GetUserNamefromToken(token:str, WorkshopName:str ="dszhcj"):
    '''
    从E系统token中解析用户名
    '''

    headers = {
        "Authorization": "Bearer " + token,
    }
    url = "http://" + WorkshopName + ".jwesystem.com:55000/api/identity/GetUserInfoByToken"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url, headers=headers)

    if r.status_code == 200:
        return r.json()["userName"]
    else:
        raise HTTPException(status_code=502, detail="用户名解析失败")