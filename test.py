import os
from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pymongo import MongoClient
from pydantic import BaseModel, EmailStr
from typing import Optional
from bson.objectid import ObjectId
from fastapi.responses import FileResponse, JSONResponse,PlainTextResponse
from fastapi.exceptions import RequestValidationError
from passlib.context import CryptContext

app = FastAPI()

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Hasher:
    @staticmethod
    def verify_password(plain_password, hashed_password):
        """Verifies the password."""
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def get_password_hash(password):
        """The password needs to be hashed for security."""
        return pwd_context.hash(password)

# MongoDB Connection
MONGO_URI = "mongodb+srv://suxil:testdb@cluster0.lpidq.mongodb.net/?retryWrites=true&w=majority"
try:
    client = MongoClient(MONGO_URI)
    db = client["test-database"]
    users_collection = db["users"]
    files_collection = db["pdf_files"]
except Exception as e:
    raise HTTPException(status_code=500, detail=f"Database connection error: {e}")

# OAuth2 Configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Base Directory for User Files
BASE_STATIC_DIR = "user_files"
os.makedirs(BASE_STATIC_DIR, exist_ok=True)

# H
def get_user_directory(username: str) -> str:
    """Get the directory path for a specific user."""
    user_dir = os.path.join(BASE_STATIC_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def rebuild_file_mappings(username: str):
    """Rebuild the `file_mappings.txt` for a user."""
    user_dir = get_user_directory(username)
    mappings_file = os.path.join(user_dir, "file_mappings.txt")

    # Fetch all files for the user from the database
    files = files_collection.find({"username": username})

    try:
        with open(mappings_file, "w") as f:
            for file in files:
                # Write both the file ID and its file path to the mappings file
                f.write(f"{file['_id']}: {file['filename']} ({file['file_path']})\n")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update file mappings: {e}")



def authenticate_user(username: str, password: str):
    """Authenticate user by username and password."""
    user = users_collection.find_one({"username": username})
    if user and Hasher.verify_password(password, user["password"]):
        return user
    return None


def get_current_user(token: str = Depends(oauth2_scheme)):
    """Retrieve the current authenticated user."""
    user = users_collection.find_one({"username": token})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

# Pydantic Models
class SignupRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

# Error Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """This isused for handling Validation Errors ...................."""
    return JSONResponse(
        status_code=422,
        content={"message": "Validation error", "errors": exc.errors()},
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """handle general exceptions occured during the app"""
    return JSONResponse(
        status_code=500,
        content={"message": f"An error occurred: {str(exc)}"},
    )

# Routes
@app.post("/signup/")
async def signup(user: SignupRequest):
    """Signup route to register a new user."""
    if users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail=f"Username {user.username} already exists")
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already exists")

    hashed_password = Hasher.get_password_hash(user.password)
    users_collection.insert_one({
        "username": user.username,
        "email": user.email,
        "password": hashed_password
    })

    # Create user-specific directory
    get_user_directory(user.username)

    return {"message": f"User {user.username}  created successfully"}


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login route to generate an access token."""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"access_token": user["username"], "token_type": "bearer"}


@app.post("/upload/")
async def upload_file(
    file: UploadFile = File(...),
    description: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Upload a file for the current user."""
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")

    user_dir = get_user_directory(current_user["username"])
    file_path = os.path.join(user_dir, file.filename)

    file_data = await file.read()
    with open(file_path, "wb") as f:
        f.write(file_data)

    file_metadata = {
        "username": current_user["username"],
        "filename": file.filename,
        "description": description,
        "file_path": file_path
    }
    files_collection.insert_one(file_metadata)

    # Update file mappings
    rebuild_file_mappings(current_user["username"])

    return {"message": f"File uploaded successfully", "filename": file.filename}


@app.get("/files/")
async def list_files(current_user: dict = Depends(get_current_user)):
    """List files for the current user."""
    files = files_collection.find({"username": current_user["username"]})
    files_list = [{"file_id": str(file["_id"]), "filename": file["filename"]} for file in files]

    if not files_list:
        return {"message": "No files uploaded yet... Please upload a file"}

    return {"files": files_list}


#StaticFile-For-pdf-viewing
@app.get("/files/{filename}")
async def view_file(filename: str, current_user: dict = Depends(get_current_user)):
    user_dir = get_user_directory(current_user["username"])
    file_path = os.path.join(user_dir, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(file_path, media_type="application/pdf", headers={"Content-Disposition": f"inline; filename={filename}"})

@app.put("/files/rename/")
async def rename_file(
    current_user: dict = Depends(get_current_user),
    # file_id: Optional[str] = None,
    old_filename: Optional[str]=None ,
    new_filename: str =None
):
    """Rename a file for the current user and update mappings.
       Either file ID or file name can be provided for renaming."""
    
    # Validate the new filename
    if not new_filename.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Filename must end with .pdf")

    file = None

    # Handle renaming by file ID
    # if file_id:
    #     file = files_collection.find_one({"_id": ObjectId(file_id), "username": current_user["username"]})
    
    # Handle renaming by file name
    if old_filename:
        file = files_collection.find_one({"filename": old_filename, "username": current_user["username"]})

    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    current_path = file["file_path"]
    user_dir = get_user_directory(current_user["username"])
    new_path = os.path.join(user_dir, new_filename)

    # Checking if the new filename already exists
    if os.path.exists(new_path):
        raise HTTPException(status_code=400, detail="A file with the new filename already exists")

    try:
        os.rename(current_path, new_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to rename file: {e}")

    # Update file metadata in the database
    # if file_id:
    #     files_collection.update_one(
    #         {"_id": ObjectId(file_id)},
    #         {"$set": {"filename": new_filename, "file_path": new_path}}
    #     )
    
    if old_filename:
        files_collection.update_one(
            {"filename": old_filename, "username": current_user["username"]},
            {"$set": {"filename": new_filename, "file_path": new_path}}
        )

    # Rebuilding file mappings
    rebuild_file_mappings(current_user["username"])

    return {"message": "File renamed successfully", "new_filename": new_filename}


@app.delete("/files/name/{filename}/")
async def delete_file_by_name(filename: str, current_user: dict = Depends(get_current_user)):
    """Deleting a file for the current user by filename."""
    # Find the file by filename and username
    file = files_collection.find_one({"filename": filename, "username": current_user["username"]})
    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    file_path = file["file_path"]
    
    #  Need to check if the file exists and delete it from the filesystem
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to delete the file: {e}")

    # file record is removed using .delete_one({'_id':file['_id']})
    files_collection.delete_one({"_id": file["_id"]})

    # Updating file mappings of the files
    rebuild_file_mappings(current_user["username"])

    return {"message": f"File '{filename}' deleted successfully"}

@app.get("/files/mappings/")
async def view_file_mappings(current_user: dict = Depends(get_current_user)):
    """
    View the file_mappings.txt file for the current user.
    """
    user_dir = get_user_directory(current_user["username"])
    mappings_file = os.path.join(user_dir, "file_mappings.txt")

    if not os.path.exists(mappings_file):
        raise HTTPException(status_code=404, detail="File mappings not found for the user")

    try:
        with open(mappings_file, "r") as f:
            content = f.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file mappings: {e}")
    if not content:
        return("message:the Mapping file is empty heeh")
    return PlainTextResponse(content)
