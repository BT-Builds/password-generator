import secrets
import string
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from mangum import Mangum

app = FastAPI(
    title="Password Generator API",
    description="Generate secure random passwords with customizable rules",
    version="1.0.0"
)

# === BT Builds Standard Middleware (auto-injected) ===
from fastapi.middleware.cors import CORSMiddleware as _BTCors
app.add_middleware(_BTCors, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], expose_headers=["X-RateLimit-Limit","X-RateLimit-Remaining","X-RateLimit-Reset"])

@app.middleware("http")
async def _bt_add_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Powered-By"] = "btbuilds"
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


# API Key auth
API_KEY_HEADER = APIKeyHeader(name="X-API-Key")

def get_api_key(key: str = Security(API_KEY_HEADER)):
    if not key:
        raise HTTPException(status_code=401, detail="API key required")
    return key

# In-memory rate limiting
rate_limit_store = {}

def rate_limit(api_key: str = Depends(get_api_key)):
    import time
    key = f"rate_{api_key}"
    current_time = int(time.time())
    minute_ago = current_time - 60
    
    if key not in rate_limit_store:
        rate_limit_store[key] = []
    
    rate_limit_store[key] = [t for t in rate_limit_store[key] if t > minute_ago]
    
    if len(rate_limit_store[key]) >= 100:
        raise HTTPException(status_code=429, detail="Rate limit exceeded (100/min)")
    
    rate_limit_store[key].append(current_time)
    return api_key

# ============== Password Generation Logic ==============
def generate_password(length: int = 16, include_uppercase: bool = True,
                    include_lowercase: bool = True, include_numbers: bool = True,
                    include_symbols: bool = True, exclude_ambiguous: bool = False,
                    count: int = 1) -> list[str]:
    """Generate one or more passwords."""
    charset = ""
    if include_lowercase:
        charset += string.ascii_lowercase
    if include_uppercase:
        charset += string.ascii_uppercase
    if include_numbers:
        charset += string.digits
    if include_symbols:
        charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if exclude_ambiguous:
        ambiguous = "l1I0O"
        charset = "".join(c for c in charset if c not in ambiguous)
    
    if not charset:
        raise ValueError("At least one character type must be enabled")
    
    if length < 4:
        raise ValueError("Password length must be at least 4")
    
    passwords = []
    for _ in range(count):
        pwd = "".join(secrets.choice(charset) for _ in range(length))
        passwords.append(pwd)
    
    return passwords[:count]


class PasswordRequest(BaseModel):
    length: int = 16
    include_uppercase: bool = True
    include_lowercase: bool = True
    include_numbers: bool = True
    include_symbols: bool = True
    exclude_ambiguous: bool = False
    count: int = 1

class PasswordResponse(BaseModel):
    passwords: list[str]
    length: int
    options: dict

# ============== Single Item Endpoints ==============
@app.get("/health")
def health():
    return {"status": "ok", "service": "password-generator-api"}

@app.post("/generate", dependencies=[Depends(rate_limit)])
def generate_endpoint(data: PasswordRequest) -> PasswordResponse:
    try:
        passwords = generate_password(
            length=data.length,
            include_uppercase=data.include_uppercase,
            include_lowercase=data.include_lowercase,
            include_numbers=data.include_numbers,
            include_symbols=data.include_symbols,
            exclude_ambiguous=data.exclude_ambiguous,
            count=data.count
        )
        return PasswordResponse(
            passwords=passwords,
            length=len(passwords),
            options={
                "include_uppercase": data.include_uppercase,
                "include_lowercase": data.include_lowercase,
                "include_numbers": data.include_numbers,
                "include_symbols": data.include_symbols,
                "exclude_ambiguous": data.exclude_ambiguous
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============== Bulk Endpoints ==============
class BulkPasswordRequest(BaseModel):
    items: list[PasswordRequest]

class BulkPasswordResponse(BaseModel):
    results: list[dict]
    total: int
    successful: int

@app.post("/bulk/generate", dependencies=[Depends(rate_limit)])
def bulk_generate(data: BulkPasswordRequest) -> BulkPasswordResponse:
    items = data.items[:1000]  # Limit to 1000
    results = []
    successful = 0
    
    for item in items:
        try:
            passwords = generate_password(
                length=item.length,
                include_uppercase=item.include_uppercase,
                include_lowercase=item.include_lowercase,
                include_numbers=item.include_numbers,
                include_symbols=item.include_symbols,
                exclude_ambiguous=item.exclude_ambiguous,
                count=item.count
            )
            results.append({
                "input": item.model_dump(),
                "output": {"passwords": passwords},
                "error": None
            })
            successful += 1
        except Exception as e:
            results.append({
                "input": item.model_dump(),
                "output": None,
                "error": str(e)
            })
    
    return BulkPasswordResponse(
        results=results,
        total=len(items),
        successful=successful
    )


# Lambda handler for Vercel
handler = Mangum(app)