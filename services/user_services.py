from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta

from core.security import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

password_hs = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


def hash_password(password):
    return password_hs.hash(password)


def verify_password(password, hashed):
    return password_hs.verify(password, hashed)


def create_token(user):
    return jwt.encode(
        {
            "sub": user.id,
            "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def get_token_user(token, db):
    from models.user_model import User
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        user_id = int(payload["sub"])
        user_query = db.query(User).filter(
            User.id == user_id
        ).first()
        return user_query

    except Exception as e:
        print("Get user token info error", str(e))
        return None

    