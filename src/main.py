from fastapi import FastAPI
# Routers
from .auth.router import router as auth

app = FastAPI(title="MrYeibis Template", version="1.0.0")

app.include_router(auth)