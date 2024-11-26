import os
from fastapi import FastAPI, Depends, HTTPException, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pymongo import MongoClient
from pydantic import BaseModel
from typing import Optional
from bson.objectid import ObjectId
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# MongoDB Connection
uri = "mongodb+srv://suxil:testdb@cluster0.lpidq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
db = client["test-database"]
collection = db["pdf_files"]

# OAuth2 Configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In-memory user storage
users = {
    "demoAPI": {
        "username": "demoAPI",
        "password": "demoapi",  # Store securely in real applications!
        "permissions": ["file_operations"]
    }
}

# Static directory for PDFs
STATIC_DIR = "static_pdfs"
os.makedirs(STATIC_DIR, exist_ok=True)

# Mount the static files directory
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# Token generation for authentication
def authenticate_user(username: str, password: str):
    user = users.get(username)
    if user and user["password"] == password:
        return {"username": username, "permissions": user["permissions"]}
    return None

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"access_token": user["username"], "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme)):
    user = users.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

# Pydantic Models
class FileMetadata(BaseModel):
    filename: str
    description: Optional[str] = None


# Helper Function to Rebuild the file_mappings.txt
def rebuild_file_mappings():
    txt_file_path = os.path.join(STATIC_DIR, "file_mappings.txt")
    
    try:
        # Retrieve all files from the database
        files = collection.find()

        # Open the file for writing
        with open(txt_file_path, "w") as txt_file:
            # Write each file's id and filename into the file
            for file in files:
                txt_file.write(f"{file['_id']}: {file['filename']}\n")
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to rebuild mapping file: {e}")


@app.post("/create/")
async def upload_file(
    file: UploadFile = File(...),
    description: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")
    
    file_data = await file.read()  # Read file as binary data
    
    # Save the file to the static directory
    file_path = os.path.join(STATIC_DIR, file.filename)
    with open(file_path, "wb") as f:
        f.write(file_data)
    
    # Insert metadata into MongoDB
    file_metadata = {
        "filename": file.filename,
        "description": description,
        "file_path": file_path
    }
    result = collection.insert_one(file_metadata)  # Store metadata in MongoDB

    # Rebuild the file mappings file based on current database state
    rebuild_file_mappings()

    return {"file_id": str(result.inserted_id), "filename": file.filename, "description": description}

@app.get("/file-mappings/")
async def get_file_mappings(current_user: dict = Depends(get_current_user)):
    txt_file_path = os.path.join(STATIC_DIR, "file_mappings.txt")
    
    try:
        # Open and read the content of the .txt file
        with open(txt_file_path, "r") as txt_file:
            content = txt_file.read()
            
        if not content:  # Check if the file is empty
            raise HTTPException(status_code=404, detail="No files available to display. The mappings file is empty.")
    
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Mapping file not found")
    
    # Return the content of the file as plain text
    return PlainTextResponse(content)

@app.get("/read/")
async def list_files(current_user: dict = Depends(get_current_user)):
    files = []
    for file in collection.find():
        files.append({"file_id": str(file["_id"]), "filename": file["filename"]})
    return files

@app.get("/view/{filename}")
async def view_pdf(filename: str):
    file_path = os.path.join(STATIC_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path, media_type="application/pdf", headers={"Content-Disposition": f"inline; filename={filename}"})

@app.delete("/delete/{file_id}")
async def delete_file(file_id: str, current_user: dict = Depends(get_current_user)):
    # Find the file in the database
    file = collection.find_one({"_id": ObjectId(file_id)})
    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    # Remove the file from the static directory
    if "file_path" in file and os.path.exists(file["file_path"]):
        os.remove(file["file_path"])

    # Delete the metadata from the database
    result = collection.delete_one({"_id": ObjectId(file_id)})

    # Rebuild the file mappings file based on current database state
    rebuild_file_mappings()

    return {"message": "File deleted successfully"}

@app.put("/rename-file/{file_id}")
async def rename_file(
    file_id: str,
    new_filename: str,
    current_user: dict = Depends(get_current_user)
):
    # Ensure the new filename has the correct extension
    if not new_filename.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Filename must end with .pdf")

    # Find the file in the database
    file = collection.find_one({"_id": ObjectId(file_id)})
    if not file:
        raise HTTPException(status_code=404, detail="File not found")

    # Get the current file path and derive the new file path
    current_path = file["file_path"]
    new_path = os.path.join(STATIC_DIR, new_filename)

    # Ensure the new filename does not already exist
    if os.path.exists(new_path):
        raise HTTPException(status_code=400, detail="A file with the new filename already exists")

    # Rename the physical file on the disk
    try:
        os.rename(current_path, new_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to rename file: {e}")

    # Update the database record
    collection.update_one(
        {"_id": ObjectId(file_id)},
        {"$set": {"filename": new_filename, "file_path": new_path}}
    )

    # Rebuild the file mappings file based on current database state
    rebuild_file_mappings()

    return {"message": "File renamed successfully", "new_filename": new_filename}

# @app.delete("/delete-by-filename/{filename}")
# async def delete_by_filename(filename: str, current_user: dict = Depends(get_current_user)):
#     # Find the file in the database
#     file = collection.find_one({"filename": filename})
#     if not file:
#         raise HTTPException(status_code=404, detail="File not found")

#     # Remove the file from the static directory
#     if "file_path" in file and os.path.exists(file["file_path"]):
#         os.remove(file["file_path"])

#     # Delete the metadata from the database
#     collection.delete_one({"filename": filename})

#     # Rebuild the file mappings file based on current database state
#     rebuild_file_mappings()

#     return {"message": f"File with filename '{filename}' deleted successfully"}
