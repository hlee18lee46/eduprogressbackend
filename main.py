from fastapi import APIRouter, FastAPI, Depends, HTTPException, status
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
from openai import OpenAI
from langchain_google_genai import ChatGoogleGenerativeAI

from langchain.schema import HumanMessage, SystemMessage

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


router = APIRouter()


# MongoDB setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client['hancluster']
user_collection = db['users']
profile_collection = db["profile"]
chat_collection = db["chats"]
quiz_collection = db["quizzes"]
assignment_collection = db["assignments"]
quiz_result_collection = db["quiz_result"]

# JWT setup
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# Gemini API key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

llm = ChatGoogleGenerativeAI(
    model="gemini-1.5-pro",
    google_api_key=GEMINI_API_KEY,
)


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

    # Fetch Canvas access token
    canvas_token = user.get("access_token_raw")  # Store this in plain text or decrypt if hashed
    canvas_base_url = user.get("canvas_base_url")
    headers = {"Authorization": f"Bearer {canvas_token}"}

    try:
        # Fetch courses
        course_resp = requests.get(f"{canvas_base_url}/api/v1/courses", headers=headers)
        courses = course_resp.json()

        for course in courses:
            course_id = course["id"]
            assignments_resp = requests.get(
                f"{canvas_base_url}/api/v1/courses/{course_id}/assignments",
                headers=headers
            )
            assignments = assignments_resp.json()
            for assignment in assignments:
                db["assignments"].update_one(
                    {"id": assignment["id"], "username": user["username"]},
                    {"$set": {
                        "username": user["username"],
                        "course_id": course_id,
                        "name": assignment.get("name"),
                        "due_at": assignment.get("due_at"),
                        "points_possible": assignment.get("points_possible"),
                        "description": assignment.get("description"),
                        "submission_types": assignment.get("submission_types"),
                        "grading_type": assignment.get("grading_type"),
                    }},
                    upsert=True
                )

    except Exception as e:
        print(f"Error during assignment sync: {e}")

    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token2")
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
    

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

class ChatRequest(BaseModel):
    message: str

@router.post("/chat")
def chat_with_gpt(chat: ChatRequest, username: str = Depends(get_current_user)):
    try:
        # 🎯 Fetch upcoming assignments for this user
        assignments = list(assignment_collection.find(
            {"username": username},
            {"_id": 0, "name": 1, "due_at": 1, "course_id": 1}
        ))

        # 📅 Parse and sort by due date (nearest upcoming first)
        def parse_due_date(a):
            try:
                return datetime.fromisoformat(a["due_at"].replace("Z", "+00:00"))
            except:
                return datetime.max  # Push non-date items to the end

        from datetime import timezone

        now = datetime.now(timezone.utc)

        sorted_assignments = sorted(
            [
                a for a in assignments
                if a.get("due_at") and parse_due_date(a) >= now
            ],
            key=parse_due_date
        )

        # 🧾 Format assignments as bullet points
        formatted_assignments = "\n".join([
            f"- {a.get('name')} (Course ID: {a.get('course_id')}, Due: {a.get('due_at')})"
            for a in sorted_assignments[:5]  # limit to 5 closest
        ]) or "No upcoming assignments found."

        # 🧠 System prompt with context
        system_prompt = (
            "You are an academic assistant. Your job is to support the student's learning.\n"
            "Here are their upcoming assignments, sorted by due date:\n"
            f"{formatted_assignments}\n\n"
            "Answer the user's question based on this academic context when helpful."
        )

        # 🧠 Call OpenAI
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": chat.message}
            ]
        )

        reply = response.choices[0].message.content
        return {"reply": reply}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.post("/chat_backup")
def chat_with_gpt(chat: ChatRequest):
    try:
        # Define system behavior
        system_prompt = (
            "You are an academic assistant. Answer clearly and helpfully to support learning."
        )

        # GPT-3.5-turbo chat completion
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": chat.message}
            ]
        )

        reply = response.choices[0].message.content

        return {"reply": reply}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
app.include_router(router)


@app.post("/chat_gemini")
def chat_with_gemini(chat: ChatRequest):
    try:
        # Updated system prompt with context about quiz results
        system_prompt = (
            "You are an academic assistant. A student has just completed a quiz and wants feedback. "
            "Based on the score and any incorrect answers they provide, give constructive feedback, "
            "highlight weak areas, and suggest how to improve learning outcomes clearly and helpfully."
        )

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=chat.message)  # contains quiz results and possibly incorrect answers
        ]

        response = llm(messages)

        return {"reply": response.content}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gemini error: {str(e)}")

@app.get("/canvas/courses/{course_id}/assignments/save2")
def save_assignments(course_id: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Fetch assignments from Canvas
        headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
        url = f"{BASE_URL}/api/v1/courses/{course_id}/assignments"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Failed to fetch assignments")

        assignments = response.json()
        assignment_collection = db["assignments"]

        for assignment in assignments:
            assignment_doc = {
                "username": username,
                "canvas_course_id": course_id,
                "assignment_id": assignment.get("id"),
                "name": assignment.get("name"),
                "due_at": assignment.get("due_at"),
                "points_possible": assignment.get("points_possible"),
                "submission_types": assignment.get("submission_types"),
                "grading_type": assignment.get("grading_type"),
                "description": assignment.get("description"),
            }

            # Upsert each assignment
            assignment_collection.update_one(
                {"assignment_id": assignment.get("id"), "username": username},
                {"$set": assignment_doc},
                upsert=True
            )

        return {"message": "Assignments saved successfully", "count": len(assignments)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
    
@app.get("/canvas/courses/{course_id}/assignments/save")
def save_and_return_assignments(course_id: int, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Fetch from Canvas API
        endpoint = f"/courses/{course_id}/assignments"
        assignments_data = get_canvas_data(endpoint)

        assignment_collection = db["assignments"]
        saved_assignments = []

        for item in assignments_data:
            assignment = {
                "username": username,
                "canvas_course_id": course_id,
                "name": item.get("name"),
                "due_at": item.get("due_at"),
                "points_possible": item.get("points_possible"),
                "grade": item.get("grade"),  # If available
            }
            assignment_collection.update_one(
                {
                    "username": username,
                    "canvas_course_id": course_id,
                    "name": item.get("name"),
                },
                {"$set": assignment},
                upsert=True
            )
            saved_assignments.append(assignment)

        return {
            "message": "Assignments saved successfully",
            "assignments": saved_assignments
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save assignments: {str(e)}")
    
@app.get("/quizzes")
def get_quizzes():
    try:
        quizzes = list(quiz_collection.find({}, {"_id": 0}))
        return {"quizzes": quizzes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching quizzes: {str(e)}")