from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from typing import List, Optional
from datetime import timedelta
from dotenv import load_dotenv
from sqlalchemy import Column, Integer, String, Float
from fastapi import Depends

import os

# Load environment variables
load_dotenv()

# Initialize the FastAPI app
app = FastAPI()

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a base class for SQLAlchemy models
Base = declarative_base()

# Password hashing and verification
password_hasher = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# JWT settings
SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = "HS256"


# Create the users table
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    full_name = Column(String)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


# Create the database tables
Base.metadata.create_all(bind=engine)


# Pydantic model for user registration
class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str


# Pydantic model for user data response
class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    created_at: datetime


# JWT token response model
class Token(BaseModel):
    access_token: str
    token_type: str


# Function to create a new user
def create_user(db: Session, user: UserCreate):
    db_user = User(username=user.username, email=user.email, full_name=user.full_name,
                   hashed_password=password_hasher.hash(user.password))
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# Function to retrieve a user by username
def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()


# Function to create a JWT token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Dependency to get a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Route to register a new user
@app.post("/register/", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return create_user(db, user)


# Route to authenticate a user and issue a JWT token
@app.post("/token/", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = get_user_by_username(db, form_data.username)
    if user is None or not password_hasher.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    price = Column(Float)
    quantity = Column(Integer)


Base.metadata.create_all(bind=engine)


def create_item(db: Session, item_data: dict):
    db_item = Item(**item_data)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item


def get_item_by_id(db: Session, item_id: int):
    return db.query(Item).filter(Item.id == item_id).first()


def get_all_items(db: Session):
    return db.query(Item).all()


def update_item(db: Session, item_id: int, item_data: dict):
    db_item = db.query(Item).filter(Item.id == item_id).first()
    if db_item:
        for key, value in item_data.items():
            setattr(db_item, key, value)
        db.commit()
        db.refresh(db_item)
    return db_item


def delete_item(db: Session, item_id: int):
    db_item = db.query(Item).filter(Item.id == item_id).first()
    if db_item:
        db.delete(db_item)
        db.commit()
        return db_item


# Pydantic model for item response
class ItemResponse(BaseModel):
    id: int
    name: str
    description: str
    price: float
    quantity: int


# Define the get_current_user function to retrieve the currently authenticated user
def get_current_user(token: str = Depends(oauth2_scheme)):
    # Replace this with your actual authentication logic
    # For example, decode the token, verify the user's identity, and return user information
    # You can use PyJWT or any other library to decode the token
    # For this example, we're returning a dummy username

    # Example authentication logic:
    username = "example_user"
    if username is None:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    return username

class ItemCreate(BaseModel):
    name: str
    description: str
    price: float
    quantity: int

# Route to create a new item
@app.post("/items/", response_model=ItemResponse)
def create_new_item(item_data: ItemCreate, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    db_item = Item(**item_data.dict())
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

# Route to get an item by ID
@app.get("/items/{item_id}", response_model=ItemResponse)
def read_item(item_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    item = get_item_by_id(db, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

# Route to get all items
@app.get("/items/", response_model=List[ItemResponse])
def read_items(db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    items = get_all_items(db)
    return items

class ItemUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    quantity: Optional[int] = None

# Route to update an item by ID
@app.put("/items/{item_id}", response_model=ItemResponse)
def update_item_by_id(item_id: int, item_data: ItemUpdate, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    item = update_item(db, item_id, item_data.dict(exclude_unset=True))
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

# Route to delete an item by ID
@app.delete("/items/{item_id}", response_model=ItemResponse)
def delete_item_by_id(item_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    item = delete_item(db, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
