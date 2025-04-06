from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from typing import List, Optional

app = FastAPI()

# Ensure email-validator is available
try:
    import email_validator
except ImportError:
    raise ImportError("email-validator is required")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Fake database
fake_users_db = [
    {
        "name": "Alice Doe",
        "email": "alice@gmail.com",
        "hashed_password": hash_password("password123")
    },
    {
        "name": "Bob Smith",
        "email": "bob@yahoo.fr",
        "hashed_password": hash_password("password1234")
    },
    {
        "name": "mohamed ali ",
        "email": "ali@gmail.com",
        "hashed_password": hash_password("test123")
    }
]

# Models
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    confirm_password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    name: str
    email: EmailStr
    hashed_password: str

def find_user_by_email(email: str) -> Optional[User]:
    user_data = next((user for user in fake_users_db if user["email"] == email), None)
    if user_data:
        return User(**user_data)
    return None

# Routes
@app.post("/register")
def register(request: RegisterRequest):
    if request.password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
 
    if find_user_by_email(request.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(request.password)
    new_user = {"name": request.name, "email": request.email, "hashed_password": hashed_password}
    fake_users_db.append(new_user)

    return {"message": "User registered successfully", "user": request.email}

@app.post("/login")
def login(request: LoginRequest):
    user = find_user_by_email(request.email)
    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"message": "Login successful", "user": user.email}

@app.get("/users", response_model=List[User])
def get_users():
    return [User(**user) for user in fake_users_db]
