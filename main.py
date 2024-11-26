from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from pymongo import MongoClient
from bson import ObjectId
from typing import Optional

app = FastAPI()

# MongoDB connection
uri = "mongodb+srv://suxil:testdb@cluster0.lpidq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
db = client["test-data"]
collection = db["collection"]

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models for validation
class ItemModel(BaseModel):
    name: str
    description: Optional[str] = None
    price: Optional[float] = None

class UpdateItemModel(BaseModel):
    name: Optional[str]
    description: Optional[str]
    price: Optional[float]

# User credentials for authentication
user_credentials = {"username": "demo", "password": "demo"}

def authenticate_user(username: str, password: str):
    if username == user_credentials["username"] and password == user_credentials["password"]:
        return True
    return False

async def get_current_user(token: str = Depends(oauth2_scheme)):
    if token != user_credentials["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token

# Authentication endpoint
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_user(form_data.username, form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": form_data.username, "token_type": "bearer"}

# Base endpoint
@app.get("/")
async def root():
    return {"message": "Explore FastAPI"}

# CRUD Operations with Authentication
@app.post("/create/")
async def create_item(item: ItemModel, current_user: str = Depends(get_current_user)):
    item_dict = item.dict()
    result = collection.insert_one(item_dict)
    return {"id": str(result.inserted_id)}

@app.get("/read/{item_id}")
async def read_item(item_id: str, current_user: str = Depends(get_current_user)):
    try:
        item = collection.find_one({"_id": ObjectId(item_id)})
        if item:
            item["_id"] = str(item["_id"])
            return item
        raise HTTPException(status_code=404, detail="Item not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/readAll/")
async def read_items(current_user: str = Depends(get_current_user)):
    try:
        items = collection.find()  # Retrieve all documents from the collection
        all_items = []
        for item in items:
            item["_id"] = str(item["_id"])  # Convert ObjectId to string
            all_items.append(item)
        return all_items
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.put("/update/{item_id}")
async def update_item(item_id: str, updated_item: UpdateItemModel, current_user: str = Depends(get_current_user)):
    try:
        update_data = {k: v for k, v in updated_item.dict().items() if v is not None}
        if not update_data:
            raise HTTPException(status_code=400, detail="No valid fields to update")
        result = collection.update_one({"_id": ObjectId(item_id)}, {"$set": update_data})
        return {"modified_count": result.modified_count}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/delete/{item_id}")
async def delete_item(item_id: str, current_user: str = Depends(get_current_user)):
    try:
        result = collection.delete_one({"_id": ObjectId(item_id)})
        return {"deleted_count": result.deleted_count}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
