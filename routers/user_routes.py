from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from schemas.user_schema import LoginRequest, RoleCreate, UserCreate
from models.db import get_db
from models.user_model import User, Roles
from services.user_services import (
    hash_password,
    verify_password,
    create_token,
    get_token_user
)

router = APIRouter()

def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization:
        raise HTTPException(401, "Token required")

    token = authorization.replace("Bearer ", "")
    user = get_token_user(token, db)

    if not user:
        raise HTTPException(401, "Invalid token")
    return user


def check_role(*roles):
    def checker(user=Depends(get_current_user)):
        if user.roles.name not in roles:
            raise HTTPException(
                status_code=403,
                detail="Permission denied"
            )
        return user

    return checker

@router.post("/create_role")
def create_roles(data: RoleCreate, db: Session = Depends(get_db)):
    try:
        exs_role = db.query(Roles).filter(Roles.name == data.role.strip()).first()
        if exs_role:
            raise HTTPException(400, "Role already exists")
        role = Roles(name=data.role)
        db.add(role)
        db.commit()
        db.refresh(role)

        return JSONResponse(
            status_code=200,
            content={
                "status": True,
                "data": {
                    "message": "Role created successfully",
                    "rolename": data.role
                }
            }
        )
    except Exception as e:
        print("Unexpected error in create role", str(e))
        return JSONResponse(
            status_code=500,
            content={
                "status": False,
                "data": {
                    "message": "Internal Server Error"
                }
            }
        )


@router.post("/login")
def login(
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    try:
        user: User = db.query(User).filter(
            User.username == data.username
        ).first()

        if not user or not verify_password(data.password, user.password):
            raise HTTPException(401, "Invalid credentials")
        user_access_token = create_token(user)
        
        return JSONResponse(
            status_code=200,
            content={
                "status": True,
                "data": {
                    "message": "User logged in successfully",
                    "access_token": user_access_token,
                    "role": user.roles.name
                }
            }
        )
    
    except Exception as e:
        print("Unexpected error in user login", str(e))
        return JSONResponse(
            status_code=500,
            content={
                "status": False,
                "data": {
                    "message": "Internal Server Error"
                }
            }
        )

@router.post("/setup/initial-admin")
def create_initial_admin(
    data: UserCreate,
    db: Session = Depends(get_db)
):
    exs_role = db.query(Roles).filter(Roles.name == "admin").first()
    if not exs_role:
        return JSONResponse(
            status_code=400,
            content={
                "status": True,
                "data": {
                    "message": "You need to create admin role first",
                }
            }
        )
    admin_exists = db.query(User).filter(User.roles.has(name="admin")).first()
    if admin_exists:
        return JSONResponse(
            status_code=400,
            content={
                "status": True,
                "data": {
                    "message": "Initial admin already exists",
                }
            }
        )

    user = User(
        name=data.name,
        username=data.username,
        password=hash_password(data.password),
        roles=exs_role
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user

@router.post("/users")
def create_user(
    data: UserCreate,
    db: Session = Depends(get_db),
    role_check=Depends(check_role("admin"))
):
    try:
        existing_user = db.query(User).filter(User.username == data.username).first()
        if existing_user:
            raise HTTPException(400, "Username already exists")
        
        user: User = User(
            name=data.name,
            username=data.username,
            password=hash_password(data.password),
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return JSONResponse(
            status_code=200,
            content={
                "status": True,
                "data": {
                    "message": "User created",
                    "id": user.id
                }
            }
        )
    except Exception as e:
        print("Unexpected error in user creation", str(e))
        return JSONResponse(
            status_code=500,
            content={
                "status": False,
                "data": {
                    "message": "Internal Server Error"
                }
            }
        )


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    role_check=Depends(check_role("admin"))
):
    try:
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            raise HTTPException(404, "User not found")

        db.delete(user)
        db.commit()

        return JSONResponse(
            status_code=200,
            content={
                "status": True,
                "data": {
                    "message": "User deleted",
                    "user_id": user.id
                }
            }
        )
    
    except Exception as e:
        print("Unexpected error in delete login", str(e))
        return JSONResponse(
            status_code=500,
            content={
                "status": False,
                "data": {
                    "message": "Internal Server Error"
                }
            }
        )