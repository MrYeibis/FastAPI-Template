from fastapi import APIRouter, HTTPException, Response, Depends, Form
# Database
from . import models
from ..database import engine
from sqlalchemy.orm import Session
from ..dependencies import get_db
# Schemas
from .schemas import User, UserCreate
# Utils
from .utils import AuthHandler, UsersHandler

models.Base.metadata.create_all(bind=engine)

router = APIRouter(tags=["Auth"])

auth_handler = AuthHandler()
users = []

@router.post(
    path='/register',
    response_model=User,
    status_code=201
    )
def register(
    email: str = Form(...),
    username: str = Form(...,min_length=4, max_length=18),
    password: str = Form(..., min_length=6, max_length=64),
    db: Session = Depends(get_db)
    ):
    if any(x.email == email for x in UsersHandler.get_users(db)):
        raise HTTPException(status_code=400, detail='Email is already registered')
    elif any(x.username == username for x in UsersHandler.get_users(db)):
        raise HTTPException(status_code=400, detail='Username is taken')
    hashed_password = auth_handler.get_password_hash(password)
    user = UsersHandler.create_user(db, UserCreate(email=email, password=password, username=username), hashed_password)
    return user


@router.post(
    path='/login',
    )
def login(
    response: Response,
    username: str = Form(...,min_length=4, max_length=18),
    password: str = Form(..., min_length=6, max_length=64),
    db: Session = Depends(get_db),
    ):
    user = None
    user = UsersHandler.get_user_by_username(db, username)
    if (user is None) or (not auth_handler.verify_password(password, user.hashed_password)):
        raise HTTPException(status_code=401, detail='Invalid username and/or password')
    token = auth_handler.encode_token(user.username)
    response.set_cookie(key="Authentication", value=token)
    return { 'token': token }

@router.get('/unprotected')
def unprotected():
    return { 'hello': 'world' }


@router.get('/protected')
def protected(username=Depends(auth_handler.auth_wrapper)):
    return { 'name': username }