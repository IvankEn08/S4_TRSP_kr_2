from fastapi import FastAPI, Response, HTTPException, Cookie, Request, Depends, Header
import json
import logging
import time
import re
from uuid import UUID, uuid4
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr, field_validator
from fastapi.responses import JSONResponse
from itsdangerous import BadSignature, Signer


SECRET_KEY = "super-secret-key-for-session-signing"
SESSION_COOKIE_NAME = "session_token"
SESSION_MAX_AGE = 300
SESSION_REFRESH_AGE = 180
signer = Signer(SECRET_KEY)

class UserCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    age: int = Field(..., gt=0, lt=120)
    is_subscribed: bool
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class CommonHeaders(BaseModel):
    user_agent: str = Field(..., alias="User-Agent")
    accept_language: str = Field(..., alias="Accept-Language")

    @field_validator("accept_language")
    @classmethod
    def validate_accept_language(cls, value: str) -> str:
        pattern = r"^[a-zA-Z]{2,3}(?:-[a-zA-Z]{2})?(?:\s*;\s*q=(?:0(?:\.\d+)?|1(?:\.0+)?))?(?:\s*,\s*[a-zA-Z]{2,3}(?:-[a-zA-Z]{2})?(?:\s*;\s*q=(?:0(?:\.\d+)?|1(?:\.0+)?))?)*$"
        if not re.fullmatch(pattern, value):
            raise ValueError("Invalid Accept-Language format")
        return value


users = [
    {
        "user_id": str(uuid4()),
        "name": "string",
        "email": "user@example.com",
        "age": 1,
        "is_subscribed": True,
        "password": "string",
    }
]

sample_product_1 = {
 "product_id": 123,
 "name": "Smartphone",
 "category": "Electronics",
 "price": 599.99
}
sample_product_2 = {
 "product_id": 456,
 "name": "Phone Case",
 "category": "Accessories",
 "price": 19.99
}
sample_product_3 = {
 "product_id": 789,
 "name": "Iphone",
 "category": "Electronics",
 "price": 1299.99
}
sample_product_4 = {
 "product_id": 101,
 "name": "Headphones",
 "category": "Accessories",
 "price": 99.99
}
sample_product_5 = {
 "product_id": 202,
 "name": "Smartwatch",
 "category": "Electronics",
 "price": 299.99
}

products = [sample_product_1, sample_product_2, sample_product_3,
sample_product_4, sample_product_5]


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app1 = FastAPI()

@app1.post("/create-user")
def add_user(user: UserCreate):
    user_data = user.model_dump()
    user_data["user_id"] = str(uuid4())
    users.append(user_data)
    logger.info("User added")
    return user_data

@app1.get("/users")
def get_users():
    logger.info("Users retrieved")
    return {"users": users}

@app1.get("/product/{product_id}")
def get_product(product_id: int):
    logger.info(f"Product {product_id} retrieved")
    return {"product": next((product for product in products if product["product_id"] == product_id), None)}

@app1.get("/products/search")
def search_products(keyword: str = None, category: str = None, limit: int = 10):
    logger.info("Products searched")
    filtered_products = products
    if keyword:
        filtered_products = [product for product in filtered_products if keyword.lower() in product["name"].lower()]
    if category:
        filtered_products = [product for product in filtered_products if category.lower() == product["category"].lower()]
    return {"products": filtered_products[:limit]}


def get_common_headers(
    user_agent: str | None = Header(default=None, alias="User-Agent"),
    accept_language: str | None = Header(default=None, alias="Accept-Language"),
) -> CommonHeaders:
    if not user_agent or not accept_language:
        raise HTTPException(status_code=400, detail="Required headers are missing")

    try:
        return CommonHeaders.model_validate(
            {
                "User-Agent": user_agent,
                "Accept-Language": accept_language,
            }
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid Accept-Language format") from exc


@app1.get("/headers")
def get_headers(headers: CommonHeaders = Depends(get_common_headers)):
    return {
        "User-Agent": headers.user_agent,
        "Accept-Language": headers.accept_language,
    }


@app1.get("/info")
def get_info(response: Response, headers: CommonHeaders = Depends(get_common_headers)):
    response.headers["X-Server-Time"] = datetime.now().isoformat(timespec="seconds")
    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": headers.user_agent,
            "Accept-Language": headers.accept_language,
        },
    }

async def parse_login_data(request: Request) -> LoginRequest:
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        payload = await request.json()
    else:
        form_data = await request.form()
        payload = dict(form_data)

    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail="Invalid login payload") from exc

    if isinstance(payload, dict) and "login_data" in payload and isinstance(payload["login_data"], str):
        try:
            payload = json.loads(payload["login_data"])
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail="Invalid login payload") from exc

    try:
        return LoginRequest.model_validate(payload)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Invalid login payload") from exc


def ensure_user_id(user: dict) -> str:
    user_id = user.get("user_id")
    if user_id:
        UUID(user_id)
        return user_id

    new_user_id = str(uuid4())
    user["user_id"] = new_user_id
    return new_user_id


def session_error_response(message: str):
    return JSONResponse(status_code=401, content={"message": message})


def build_session_token(user_id: str, last_activity: int) -> str:
    return signer.sign(f"{user_id}.{last_activity}").decode()


def set_session_cookie(response: Response, user_id: str, last_activity: int):
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=build_session_token(user_id, last_activity),
        httponly=True,
        max_age=SESSION_MAX_AGE,
        secure=False,
        samesite="lax",
    )


@app1.post("/login")
async def login(request: Request, response: Response):
    credentials = await parse_login_data(request)
    match = next(
        (u for u in users if u["email"] == credentials.email and u["password"] == credentials.password),
        None,
    )
    if not match:
        return session_error_response("Invalid session")

    user_id = ensure_user_id(match)
    last_activity = int(time.time())
    token = build_session_token(user_id, last_activity)
    set_session_cookie(response, user_id, last_activity)
    return {"message": f"session token: {token}"}

def get_user_by_signed_token(session_token: str | None):
    if not session_token:
        return {"error": "Invalid session"}

    try:
        unsigned_value = signer.unsign(session_token).decode()
        user_id, last_activity_raw = unsigned_value.rsplit(".", 1)
        UUID(user_id)
        last_activity = int(last_activity_raw)
    except (BadSignature, ValueError, TypeError):
        return {"error": "Invalid session"}

    now = int(time.time())
    elapsed = now - last_activity
    if elapsed < 0 or elapsed >= SESSION_MAX_AGE:
        return {"error": "Session expired"}

    user = next((u for u in users if u.get("user_id") == user_id), None)
    if not user:
        return {"error": "Invalid session"}

    should_refresh = SESSION_REFRESH_AGE <= elapsed < SESSION_MAX_AGE
    return {
        "user": user,
        "should_refresh": should_refresh,
        "last_activity": last_activity,
        "current_timestamp": now,
    }


@app1.get("/profile")
def get_profile(
    response: Response,
    session_token: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
):
    session_data = get_user_by_signed_token(session_token)
    if "error" in session_data:
        return session_error_response(session_data["error"])

    user = session_data["user"]
    if session_data["should_refresh"]:
        set_session_cookie(response, user["user_id"], session_data["current_timestamp"])

    return {
        "user_id": user["user_id"],
        "name": user["name"],
        "email": user["email"],
        "age": user["age"],
        "is_subscribed": user["is_subscribed"]
    }


@app1.get("/user")
def get_user(
    response: Response,
    session_token: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
):
    session_data = get_user_by_signed_token(session_token)
    if "error" in session_data:
        return session_error_response(session_data["error"])

    user = session_data["user"]
    if session_data["should_refresh"]:
        set_session_cookie(response, user["user_id"], session_data["current_timestamp"])

    return {
        "user_id": user["user_id"],
        "name": user["name"],
        "email": user["email"],
        "age": user["age"],
        "is_subscribed": user["is_subscribed"]
    }

# uvicorn t3-1:app1 --reload --port 8002
