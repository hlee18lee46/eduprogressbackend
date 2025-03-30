from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from passlib.context import CryptContext
import requests
import os
from dotenv import load_dotenv
import jwt
from fastapi import Request
from datetime import datetime, timedelta
from bson.objectid import ObjectId
import google.generativeai as genai

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
profile_collection = db["profile"]
chat_collection = db["chats"]

# JWT setup
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# Gemini API key
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

class User(BaseModel):
    username: str
    password: str
    canvas_base_url: str
    access_token: str

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
    hashed_token = get_password_hash(user.access_token)

    # Insert user into the users collection
    user_collection.insert_one({
        "username": user.username,
        "password": hashed_password,
        "canvas_base_url": user.canvas_base_url,
        "access_token": hashed_token,
    })

    # Store raw Canvas credentials temporarily to fetch data
    BASE_URL = user.canvas_base_url
    ACCESS_TOKEN = user.access_token
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}

    try:
        # ✅ 1. Fetch and store profile
        profile_url = f"{BASE_URL}/api/v1/users/self/profile"
        profile_resp = requests.get(profile_url, headers=headers)
        profile_data = profile_resp.json()

        if profile_resp.status_code != 200:
            raise HTTPException(status_code=profile_resp.status_code, detail="Failed to fetch profile")

        profile_doc = {
            "login_id": user.username,
            "name": profile_data.get("name"),
            "primary_email": profile_data.get("primary_email"),
            "time_zone": profile_data.get("time_zone"),
        }
        db["profile"].update_one(
            {"login_id": user.username},
            {"$set": profile_doc},
            upsert=True
        )

        # ✅ 2. Fetch and store courses
        course_url = f"{BASE_URL}/api/v1/courses"
        course_resp = requests.get(course_url, headers=headers)
        course_data = course_resp.json()

        if course_resp.status_code != 200:
            raise HTTPException(status_code=course_resp.status_code, detail="Failed to fetch courses")

        for course in course_data:
            course_doc = {
                "username": user.username,
                "canvas_course_id": course.get("id"),
                "name": course.get("name"),
                "course_code": course.get("course_code"),
                "start_at": datetime.fromisoformat(course["start_at"].replace("Z", "+00:00")) if course.get("start_at") else None,
                "end_at": datetime.fromisoformat(course["end_at"].replace("Z", "+00:00")) if course.get("end_at") else None,
                "term_id": course.get("enrollment_term_id"),
                "calendar_ics": course.get("calendar", {}).get("ics"),
                "uuid": course.get("uuid"),
                "time_zone": course.get("time_zone")
            }

            db["courses"].update_one(
                {"canvas_course_id": course.get("id"), "username": user.username},
                {"$set": course_doc},
                upsert=True
            )

        return {"message": "User registered and Canvas data saved successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error during Canvas sync: {str(e)}")


@app.post("/register2")
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



# Dependency to get the current user
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username

@app.post("/canvas/profile/insert")
async def insert_profile(request: Request, current_user: str = Depends(get_current_user)):
    profile_data = await request.json()

    insert_data = {
        "name": profile_data.get("name"),
        "primary_email": profile_data.get("primary_email"),
        "time_zone": profile_data.get("time_zone"),
        "login_id": current_user  # Use the username from the JWT token
    }

    result = profile_collection.update_one(
        {"login_id": current_user},  # filter by the authenticated user's username
        {"$set": insert_data},       # update operation
        upsert=True                  # insert if not found
    )

    return {
        "message": "Profile inserted or updated",
        "login_id": current_user,
        "matched_count": result.matched_count,
        "modified_count": result.modified_count,
        "upserted_id": str(result.upserted_id) if result.upserted_id else None
    }




@app.get("/canvas/courses/save")
def save_courses(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        canvas_data = get_canvas_data("/courses")
        if not canvas_data:
            raise HTTPException(status_code=404, detail="No courses found from Canvas API.")

        course_collection = db["courses"]

        for course in canvas_data:
            record = {
                "username": username,  # ✅ Store user's username
                "canvas_course_id": course.get("id"),
                "name": course.get("name"),
                "course_code": course.get("course_code"),
                "start_at": datetime.fromisoformat(course["start_at"].replace("Z", "+00:00")) if course.get("start_at") else None,
                "end_at": datetime.fromisoformat(course["end_at"].replace("Z", "+00:00")) if course.get("end_at") else None,
                "term_id": course.get("enrollment_term_id"),
                "calendar_ics": course.get("calendar", {}).get("ics"),
                "uuid": course.get("uuid"),
                "time_zone": course.get("time_zone")
            }

            course_collection.update_one(
                {"canvas_course_id": course.get("id"), "username": username},
                {"$set": record},
                upsert=True
            )

        return {"message": "Courses saved successfully", "count": len(canvas_data)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/courses")
def get_saved_courses(token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    course_collection = db["courses"]
    courses = list(course_collection.find({"username": username}, {"_id": 0}))  # exclude _id
    return courses

@app.delete("/courses/delete_all")
def delete_all_courses(token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    course_collection = db["courses"]
    result = course_collection.delete_many({"username": username})

    return {
        "message": f"Deleted {result.deleted_count} courses for user '{username}'."
    }

from fastapi import Depends, HTTPException
from bson.json_util import dumps
from bson.objectid import ObjectId

@app.get("/profile")
def get_profile(token: str = Depends(oauth2_scheme)):
    try:
        # Decode JWT token to get username
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Look for user profile using login_id (which should match the username)
        profile = db["profile"].find_one({"login_id": username}, {"_id": 0})
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")

        return profile

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
    

    # Model
class ChatRequest(BaseModel):
    message: str

# Endpoint
@app.post("/chat")
async def chat_with_gemini(chat: ChatRequest, token: str = Depends(oauth2_scheme)):
    try:
        # Get username from token
        import jwt
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Initialize Gemini model
        model = genai.GenerativeModel("gemini-pro")

        # Create conversation prompt
        system_prompt = (
            f"You are an academic assistant. Provide helpful, clear, and insightful answers to the user's query."
        )

        response = model.generate_content([
            {"role": "system", "parts": [system_prompt]},
            {"role": "user", "parts": [chat.message]}
        ])

        # Extract reply
        reply = response.text

        # Optionally store chat history
        chat_collection.insert_one({
            "username": username,
            "question": chat.message,
            "response": reply
        })

        return {"reply": reply}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chatbot error: {str(e)}")