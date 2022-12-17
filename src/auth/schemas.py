from pydantic import BaseModel, Field

class PasswordMixin(BaseModel):
    password: str = Field(..., min_length=6, max_length=64)

class UserBase(BaseModel):
    email: str = Field(...)

class UserCreate(PasswordMixin, UserBase):
    username: str = Field(..., min_length=4, max_length=18)

class UserLogin(UserBase, PasswordMixin):
    pass

class User(UserBase):
    id: int
    username: str
    is_active: bool
    
    class Config:
        orm_mode = True