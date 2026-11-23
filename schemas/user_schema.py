from pydantic import BaseModel

class RoleCreate(BaseModel):
    role: str

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    name: str
    username: str
    password: str

