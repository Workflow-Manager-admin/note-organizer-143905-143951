from fastapi import FastAPI, Depends, HTTPException, status, Query, Path
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import jwt
import os
from datetime import datetime, timedelta

from src.database import (
    User, Note, Category, get_db, init_db
)

# --- FastAPI App Initialization ---

app = FastAPI(
    title="Notes Organizer Backend API",
    description="API endpoints for a Notes application backend with authentication, note/category/user management, search/filter, and environment support.",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "Authentication endpoints (login, signup, token)."},
        {"name": "users", "description": "User management."},
        {"name": "notes", "description": "CRUD operations for notes, with search/filter."},
        {"name": "categories", "description": "Manage note categories."}
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # You may restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security / Auth setup ---

SECRET_KEY = os.environ.get("NOTES_SECRET_KEY", "dev-secret")  # Don't use this default in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("NOTES_ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


# PUBLIC_INTERFACE
def verify_password(plain_password, hashed_password):
    """Verify a plain password against a hashed one."""
    return pwd_context.verify(plain_password, hashed_password)

# PUBLIC_INTERFACE
def get_password_hash(password):
    """Hash a plaintext password."""
    return pwd_context.hash(password)

# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a new JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# PUBLIC_INTERFACE
def decode_access_token(token: str):
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

# PUBLIC_INTERFACE
def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    """Dependency: retrieves current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not authenticate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise credentials_exception
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# ------------------ Pydantic Schemas ------------------

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., min_length=6, max_length=255, description="Password")

class UserRead(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class CategoryRead(BaseModel):
    id: int
    name: str

    class Config:
        orm_mode = True

class CategoryCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)

class NoteRead(BaseModel):
    id: int
    title: str
    content: Optional[str]
    category: Optional[CategoryRead]
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class NoteCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    content: Optional[str]
    category_id: Optional[int] = Field(None, description="ID of category (optional)")

class NoteUpdate(BaseModel):
    title: Optional[str]
    content: Optional[str]
    category_id: Optional[int]


# ---------------- HEALTH CHECK -----------------

@app.get("/", tags=["health"], summary="Health Check", description="Verify that the API is up.")
def health_check():
    """Returns a simple message to indicate health status."""
    return {"message": "Healthy"}

# ----------------- AUTHENTICATION -----------------

# PUBLIC_INTERFACE
@app.post("/auth/signup", tags=["auth"], summary="Sign Up", response_model=UserRead)
def signup(user_in: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user.
    """
    if db.query(User).filter((User.username == user_in.username) | (User.email == user_in.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already registered.")

    hashed_pwd = get_password_hash(user_in.password)
    user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hashed_pwd,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

# PUBLIC_INTERFACE
@app.post("/auth/token", tags=["auth"], response_model=Token, summary="User login and get JWT token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Authenticate a user and return an access token.
    """
    user = db.query(User).filter((User.username == form_data.username) | (User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password.")
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}


# ----------- USERS ENDPOINTS -------------

# PUBLIC_INTERFACE
@app.get("/users/me", response_model=UserRead, tags=["users"], summary="Get current user")
def read_users_me(current_user: User = Depends(get_current_user)):
    """Return current authenticated user."""
    return current_user


# ---------- CATEGORY ENDPOINTS ------------

# PUBLIC_INTERFACE
@app.get("/categories", response_model=List[CategoryRead], tags=["categories"], summary="Get user's categories")
def get_categories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all categories owned by current user."""
    cats = db.query(Category).filter(Category.owner_id == current_user.id).all()
    return cats

# PUBLIC_INTERFACE
@app.post("/categories", response_model=CategoryRead, tags=["categories"], summary="Create new category")
def create_category(
    cat_in: CategoryCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new category under current user."""
    exists = db.query(Category).filter(
        Category.owner_id == current_user.id, Category.name == cat_in.name
    ).first()
    if exists:
        raise HTTPException(status_code=409, detail="Category with this name already exists.")
    cat = Category(name=cat_in.name, owner_id=current_user.id)
    db.add(cat)
    db.commit()
    db.refresh(cat)
    return cat

# PUBLIC_INTERFACE
@app.delete("/categories/{category_id}", tags=["categories"], summary="Delete category")
def delete_category(
    category_id: int = Path(..., gt=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a category and all notes within it owned by the current user."""
    cat = db.query(Category).filter(
        Category.id == category_id, Category.owner_id == current_user.id
    ).first()
    if not cat:
        raise HTTPException(status_code=404, detail="Category not found.")
    db.delete(cat)
    db.commit()
    return {"ok": True}

# ------------ NOTES ENDPOINTS -------------

# PUBLIC_INTERFACE
@app.get("/notes", response_model=List[NoteRead], tags=["notes"], summary="List notes with search/filter")
def list_notes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    category_id: Optional[int] = Query(None, description="Filter by category id"),
    search: Optional[str] = Query(None, description="Search term in title/content"),
    skip: int = Query(0, ge=0, description="Pagination skip"),
    limit: int = Query(20, ge=1, le=100, description="Pagination limit"),
    sort: Optional[str] = Query("created_at_desc", description="Sort by: 'created_at_desc', 'created_at_asc', 'title_asc', 'title_desc'")
):
    """
    Get a paginated, optionally filtered list of notes for current user.
    Supports filtering by category and free text search.
    """
    q = db.query(Note).filter(Note.owner_id == current_user.id)
    if category_id:
        q = q.filter(Note.category_id == category_id)
    if search:
        q = q.filter(
            (Note.title.ilike(f"%{search}%")) |
            (Note.content.ilike(f"%{search}%"))
        )
    # Sorting
    if sort == "created_at_asc":
        q = q.order_by(Note.created_at.asc())
    elif sort == "title_asc":
        q = q.order_by(Note.title.asc())
    elif sort == "title_desc":
        q = q.order_by(Note.title.desc())
    else:  # Default and fallback
        q = q.order_by(Note.created_at.desc())
    notes = q.offset(skip).limit(limit).all()
    return notes

# PUBLIC_INTERFACE
@app.get("/notes/{note_id}", response_model=NoteRead, tags=["notes"], summary="Get note by ID")
def get_note(
    note_id: int = Path(..., gt=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a single note of the current user by id."""
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found.")
    return note

# PUBLIC_INTERFACE
@app.post("/notes", response_model=NoteRead, tags=["notes"], summary="Create note")
def create_note(
    note_in: NoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new note for the current user."""
    if note_in.category_id is not None:
        cat = db.query(Category).filter(
            Category.id == note_in.category_id,
            Category.owner_id == current_user.id
        ).first()
        if not cat:
            raise HTTPException(status_code=404, detail="Category not found.")
    note = Note(
        title=note_in.title,
        content=note_in.content,
        owner_id=current_user.id,
        category_id=note_in.category_id
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note

# PUBLIC_INTERFACE
@app.put("/notes/{note_id}", response_model=NoteRead, tags=["notes"], summary="Update note")
def update_note(
    note_id: int,
    note_in: NoteUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an existing note (any field)."""
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found.")
    if note_in.title is not None:
        note.title = note_in.title
    if note_in.content is not None:
        note.content = note_in.content
    if note_in.category_id is not None:
        if note_in.category_id:
            cat = db.query(Category).filter(Category.id == note_in.category_id, Category.owner_id == current_user.id).first()
            if not cat:
                raise HTTPException(status_code=404, detail="Category not found.")
        note.category_id = note_in.category_id
    db.commit()
    db.refresh(note)
    return note

# PUBLIC_INTERFACE
@app.delete("/notes/{note_id}", tags=["notes"], summary="Delete note")
def delete_note(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a note of the current user."""
    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found.")
    db.delete(note)
    db.commit()
    return {"ok": True}

# -------------------- DB INIT ----------------------

@app.on_event("startup")
def startup_event():
    """Initialize the database on startup if needed."""
    init_db()

