from fastapi import FastAPI, Security
from fastapi.requests import Request
from fastapi.responses import JSONResponse

from auth import AuthError, get_current_user

app = FastAPI()


@app.exception_handler(AuthError)
async def handle_auth_error(request: Request, ex: AuthError):
    return JSONResponse(status_code=ex.status_code, content=ex.error)


@app.get("/private")
async def private(user=Security(get_current_user)):
    return user


@app.get("/private-with-scopes")
async def privateScopes(user=Security(get_current_user, scopes=["openid"])):
    return {"message": "You're authorized with scopes!"}
