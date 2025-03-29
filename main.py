from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext
import requests
import os
from dotenv import load_dotenv
import jwt


from datetime import datetime, timedelta

load_dotenv()

# FastAPI app init
app = FastAPI()

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client['hancluster']
user_collection = db['users']

# JWT setup
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

class User(BaseModel):
    username: str
    password: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/register")
async def register(user: User):
    if user_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = get_password_hash(user.password)
    user_collection.insert_one({"username": user.username, "password": hashed_password})
    return {"message": "User registered successfully"}

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = user_collection.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"message": "Protected route accessed", "username": username}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Canvas LMS Integration
BASE_URL = os.getenv("CANVAS_BASE_URL")
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")

if not BASE_URL or not ACCESS_TOKEN:
    raise ValueError("CANVAS_BASE_URL or ACCESS_TOKEN not found in .env")

def get_canvas_data(endpoint: str):
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
    url = f"{BASE_URL}/api/v1{endpoint}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

@app.get("/canvas/profile")
def get_profile():
    return get_canvas_data("/users/self/profile")

@app.get("/canvas/courses")
def get_courses():
    return get_canvas_data("/courses")

@app.get("/canvas/courses/{course_id}/assignments")
def get_assignments(course_id: str):
    return get_canvas_data(f"/courses/{course_id}/assignments")