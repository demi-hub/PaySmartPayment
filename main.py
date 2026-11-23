
from fastapi import FastAPI
from models.db import Base, engine
from routers.user_routes import router

app = FastAPI(title="Admin Management System")

Base.metadata.create_all(bind=engine)

app.include_router(router)


@app.get("/")
def home():
    return {"message": "Admin Management System Running"}