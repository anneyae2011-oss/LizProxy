"""Main FastAPI application for the AI Proxy.

Provides API key generation via Google OAuth, rate limiting, and request proxying.
"""

import hashlib
import hmac
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Tuple, AsyncGenerator

import httpx
from fastapi import FastAPI, Request, HTTPException, Depends, Header, Response, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from authlib.integrations.starlette_client import OAuth

from backend.config import load_settings, Settings
from backend.database import Database, ApiKeyRecord, create_database
from backend.session_secret import get_or_create_session_secret


# ==================== Google OAuth Configuration ====================

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "https://lizley.zeabur.app/auth/callback")
# Persistent session secret from DB (no .env required; survives restarts)
SESSION_SECRET = get_or_create_session_secret(
    database_url=os.getenv("DATABASE_URL"),
    database_path=os.getenv("DATABASE_PATH", "./proxy.db"),
)

# Initialize OAuth
oauth = OAuth()
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)


# ==================== Path Configuration ====================

# Get the directory where this file is located
BACKEND_DIR = Path(__file__).parent
# Frontend directory is at the same level as backend
# Try multiple possible locations for the frontend
_possible_frontend_paths = [
    BACKEND_DIR.parent / "frontend",  # Standard: backend/../frontend
    Path.cwd() / "frontend",          # CWD/frontend (for Zeabur)
    Path("/app/frontend"),            # Absolute path in container
]
FRONTEND_DIR = None
for _path in _possible_frontend_paths:
    if _path.exists() and (_path / "index.html").exists():
        FRONTEND_DIR = _path
        break
# Fallback to the standard path even if it doesn't exist (for error messages)
if FRONTEND_DIR is None:
    FRONTEND_DIR = BACKEND_DIR.parent / "frontend"


# ==================== Pydantic Models ====================

class KeyGenerationResponse(BaseModel):
    """Response model for key generation endpoint."""
    key: Optional[str] = None  # Full key only on first generation
    key_prefix: str
    message: str
    google_email: Optional[str] = None


class AdminKeyResponse(BaseModel):
    """Response model for admin key listing."""
    id: int
    key_prefix: str
    ip_address: str
    google_email: Optional[str]
    enabled: bool
    bypass_ip_ban: bool
    current_rpm: int
    current_rpd: int  # Request count today (display)
    tokens_used_today: int  # Tokens used today (daily quota)
    created_at: str
    last_used_at: Optional[str]


class ConfigResponse(BaseModel):
    """Response model for proxy configuration."""
    target_api_url: str
    target_api_key_masked: str
    max_context: int
    max_output_tokens: int = 4096  # Max completion tokens per request (stops long outputs)
    max_keys_per_ip: int = 2  # Abuse protection: max API keys per IP


class ConfigUpdateRequest(BaseModel):
    """Request model for updating proxy configuration."""
    target_api_url: Optional[str] = None
    target_api_key: Optional[str] = None
    max_context: Optional[int] = None
    max_output_tokens: Optional[int] = None


class BypassIpRequest(BaseModel):
    """Request model for setting key bypass IP ban."""
    bypass: bool


class BanIpRequest(BaseModel):
    """Request model for banning an IP address."""
    ip_address: str
    reason: Optional[str] = None


class BannedIpResponse(BaseModel):
    """Response model for banned IP listing."""
    id: int
    ip_address: str
    reason: Optional[str]
    banned_at: str


class KeyInfoResponse(BaseModel):
    """Response model for key info endpoint."""
    key_prefix: str
    enabled: bool
    google_email: Optional[str] = None
    created_at: str
    rpm_used: int
    rpm_limit: int
    rpd_used: int
    rpd_limit: int


class UsageResponse(BaseModel):
    """Response model for usage stats endpoint."""
    rpm_used: int
    rpm_limit: int
    rpm_remaining: int
    rpd_used: int
    rpd_limit: int
    rpd_remaining: int
    total_tokens: int


class RequestLogResponse(BaseModel):
    """Response model for request log entries."""
    id: int
    key_prefix: str
    ip_address: str
    model: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    success: bool
    error_message: Optional[str]
    request_time: str


class KeyAnalyticsResponse(BaseModel):
    """Response model for key analytics."""
    key_id: int
    key_prefix: str
    ip_address: str
    total_input_tokens: int
    total_output_tokens: int
    total_tokens: int
    total_requests: int
    successful_requests: int
    most_used_model: Optional[str]
    model_usage_count: int
    recent_requests: list[RequestLogResponse]


class ErrorResponse(BaseModel):
    """Standard error response model."""
    error: str


class RateLimitErrorResponse(BaseModel):
    """Error response for rate limit exceeded."""
    error: str
    retry_after: int


class ChatMessage(BaseModel):
    """A single chat message."""
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    """Request model for chat completions."""
    model: str
    messages: list[ChatMessage]
    stream: Optional[bool] = False
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    # Allow additional fields to pass through
    model_config = {"extra": "allow"}


class RateLimitResult:
    """Result of rate limit check."""
    
    def __init__(
        self,
        allowed: bool,
        rpm_exceeded: bool = False,
        rpd_exceeded: bool = False,
        retry_after: int = 0,
        new_rpm: int = 0,
        new_rpd: int = 0,
    ):
        self.allowed = allowed
        self.rpm_exceeded = rpm_exceeded
        self.rpd_exceeded = rpd_exceeded
        self.retry_after = retry_after
        self.new_rpm = new_rpm
        self.new_rpd = new_rpd


# ==================== Constants ====================

RPM_LIMIT = 10
RPD_LIMIT = 150  # Request count (display only; daily limit is token-based)
TOKENS_PER_DAY_LIMIT = 150_000  # Daily token quota per key (enforced)
RPM_WINDOW_SECONDS = 60
MAX_TOKENS_PER_SECOND = 35  # Maximum tokens per second for streaming


# ==================== Helper Functions ====================

def generate_api_key() -> str:
    """Generate a new API key in the format sk-{32_hex_characters}.
    
    Returns:
        A new API key string.
    """
    # Generate 16 random bytes, which produces 32 hex characters
    random_hex = secrets.token_hex(16)
    return f"sk-{random_hex}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key using SHA256.
    
    Args:
        api_key: The API key to hash.
    
    Returns:
        The SHA256 hash of the key as a hex string.
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


def get_key_prefix(api_key: str) -> str:
    """Get the first 8 characters of an API key for display.
    
    Args:
        api_key: The API key.
    
    Returns:
        The first 8 characters of the key.
    """
    return api_key[:8]


def get_client_ip(request: Request) -> str:
    """Extract the client IP address from a request.
    
    Handles various proxy headers for cloud platforms like Zeabur, Cloudflare, etc.
    Validates IP format to prevent header spoofing attacks.
    
    Args:
        request: The FastAPI request object.
    
    Returns:
        The client's IP address.
    """
    import ipaddress
    
    def is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    # Check various proxy headers in order of preference
    # Different cloud platforms use different headers
    proxy_headers = [
        "CF-Connecting-IP",      # Cloudflare
        "X-Real-IP",             # Nginx, many proxies
        "X-Forwarded-For",       # Standard proxy header
        "True-Client-IP",        # Akamai, Cloudflare Enterprise
        "X-Client-IP",           # Some proxies
        "X-Original-Forwarded-For",  # Some load balancers
    ]
    
    for header in proxy_headers:
        value = request.headers.get(header)
        if value:
            # X-Forwarded-For can contain multiple IPs, take the first (original client)
            if "," in value:
                client_ip = value.split(",")[0].strip()
            else:
                client_ip = value.strip()
            
            # Validate it's a real IP to prevent spoofing
            if is_valid_ip(client_ip):
                return client_ip
    
    # Fall back to direct client IP
    if request.client and request.client.host:
        return request.client.host
    
    return "unknown"


async def check_and_update_rate_limits(
    key_record: ApiKeyRecord,
    database: "Database",
    estimated_tokens: int = 0,
) -> RateLimitResult:
    """Check rate limits for an API key and update counters if allowed.
    
    Enforces RPM (requests per minute) and daily token quota (TOKENS_PER_DAY_LIMIT).
    Uses atomic increment for request count; token usage is summed from usage_logs.
    
    Args:
        key_record: The API key record to check.
        database: The database instance for updating counters.
        estimated_tokens: Estimated tokens for this request (input + max output); used for daily token check.
    
    Returns:
        RateLimitResult indicating whether the request is allowed and any
        rate limit information.
    """
    now = datetime.now(timezone.utc)
    
    # Get current counter values (may be reset below)
    current_rpm = key_record.current_rpm
    current_rpd = key_record.current_rpd
    
    # Check if RPM needs to be reset (60+ seconds since last reset)
    last_rpm_reset = key_record.last_rpm_reset
    if last_rpm_reset.tzinfo is None:
        last_rpm_reset = last_rpm_reset.replace(tzinfo=timezone.utc)
    
    seconds_since_rpm_reset = (now - last_rpm_reset).total_seconds()
    if seconds_since_rpm_reset >= RPM_WINDOW_SECONDS:
        await database.reset_rpm(key_record.id)
        current_rpm = 0
    
    # Check if RPD counter needs to be reset (new calendar day in UTC)
    last_rpd_reset = key_record.last_rpd_reset
    if last_rpd_reset.tzinfo is None:
        last_rpd_reset = last_rpd_reset.replace(tzinfo=timezone.utc)
    
    if now.date() > last_rpd_reset.date():
        await database.reset_rpd(key_record.id)
        current_rpd = 0
    
    # Check RPM limit
    if current_rpm >= RPM_LIMIT:
        retry_after = max(1, int(RPM_WINDOW_SECONDS - seconds_since_rpm_reset))
        return RateLimitResult(
            allowed=False,
            rpm_exceeded=True,
            retry_after=retry_after,
        )
    
    # Check daily token limit (tokens per day, not request count)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    daily_tokens_used = await database.get_daily_tokens_used(
        key_record.id, today_start.isoformat(), today_end.isoformat()
    )
    if daily_tokens_used + estimated_tokens > TOKENS_PER_DAY_LIMIT:
        midnight_utc = today_end
        retry_after = int((midnight_utc - now).total_seconds())
        return RateLimitResult(
            allowed=False,
            rpd_exceeded=True,
            retry_after=retry_after,
        )
    
    # Request is allowed - atomically increment request counters
    new_rpm, new_rpd = await database.increment_usage(key_record.id)
    
    return RateLimitResult(
        allowed=True,
        new_rpm=new_rpm,
        new_rpd=new_rpd,
    )


def create_rate_limit_response(result: RateLimitResult) -> JSONResponse:
    """Create a 429 response for rate limit exceeded.
    
    Args:
        result: The RateLimitResult from check_and_update_rate_limits.
    
    Returns:
        JSONResponse with 429 status and appropriate error message.
    """
    if result.rpm_exceeded:
        message = "Rate limit exceeded. Please wait before making more requests."
    else:
        message = "Daily token limit exceeded. Resets at midnight UTC."
    
    return JSONResponse(
        status_code=429,
        content={
            "error": message,
            "retry_after": result.retry_after,
        },
        headers={"Retry-After": str(result.retry_after)},
    )


# Global database instance (initialized on startup)
db: Optional[Database] = None
settings: Optional[Settings] = None

# Global HTTP client for connection pooling (initialized on startup)
http_client: Optional[httpx.AsyncClient] = None


# ==================== Dependency Functions ====================

async def check_ip_ban(request: Request) -> str:
    """FastAPI dependency to check if the client IP is banned.
    
    This dependency should be applied to all endpoints that need IP ban checking.
    It extracts the client IP and checks if it's banned in the database.
    
    Args:
        request: The FastAPI request object.
    
    Returns:
        The client IP address if not banned.
    
    Raises:
        HTTPException: 403 Forbidden if the IP is banned.
    """
    client_ip = get_client_ip(request)
    
    if await db.is_ip_banned(client_ip):
        raise HTTPException(
            status_code=403,
            detail="Your IP address has been banned"
        )
    
    return client_ip


async def validate_api_key(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> Tuple[ApiKeyRecord, str]:
    """FastAPI dependency to validate the API key from Authorization header.
    
    Extracts the API key from the Authorization header, validates it against
    the database, and checks if the key is enabled and the IP is not banned.
    
    Args:
        request: The FastAPI request object.
        authorization: The Authorization header value.
    
    Returns:
        Tuple of (ApiKeyRecord, client_ip) if valid.
    
    Raises:
        HTTPException: 401 if key is invalid/missing, 403 if key disabled or IP banned.
    """
    # Check for Authorization header
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )
    
    # Extract the key from "Bearer sk-xxx" format
    if authorization.startswith("Bearer "):
        api_key = authorization[7:]
    else:
        api_key = authorization
    
    # Validate key format
    if not api_key.startswith("sk-"):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )
    
    # Hash the key and look it up
    key_hash = hash_api_key(api_key)
    key_record = await db.get_key_by_hash(key_hash)
    
    if not key_record:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )
    
    # Check if key is enabled
    if not key_record.enabled:
        raise HTTPException(
            status_code=403,
            detail="This API key has been disabled"
        )
    
    # Check if IP is banned (skip for keys with bypass_ip_ban set by admin)
    client_ip = get_client_ip(request)
    if not key_record.bypass_ip_ban and await db.is_ip_banned(client_ip):
        raise HTTPException(
            status_code=403,
            detail="Your IP address has been banned"
        )
    
    return key_record, client_ip


def count_tokens(messages: list[ChatMessage]) -> int:
    """Estimate the token count for a list of messages.
    
    Uses a simple heuristic: approximately 4 characters per token.
    This is a rough estimate and may not match the exact tokenization
    used by the target API.
    
    Args:
        messages: List of chat messages.
    
    Returns:
        Estimated token count.
    """
    total_chars = 0
    for message in messages:
        # Count role and content
        total_chars += len(message.role)
        total_chars += len(message.content)
        # Add overhead for message structure (approximately 4 tokens per message)
        total_chars += 16
    
    # Approximate 4 characters per token
    return total_chars // 4


async def get_max_context() -> int:
    """Get the maximum context limit from config or database.
    
    Returns:
        The max_context value.
    """
    # First try database config
    config = await db.get_config()
    if config:
        return config.max_context
    
    # Fall back to settings
    if settings:
        return settings.max_context
    
    # Default value
    return 128000


async def get_max_output_tokens() -> int:
    """Get the maximum completion tokens per request from config or database."""
    config = await db.get_config()
    if config:
        return config.max_output_tokens
    if settings:
        return settings.max_output_tokens
    return 4096


async def get_target_api_config() -> Tuple[str, str]:
    """Get the target API URL and key from config or database.
    
    Returns:
        Tuple of (target_api_url, target_api_key).
    """
    # First try database config
    config = await db.get_config()
    if config:
        return config.target_api_url, config.target_api_key
    
    # Fall back to settings
    if settings:
        return settings.target_api_url, settings.target_api_key
    
    raise HTTPException(
        status_code=500,
        detail="Proxy not configured"
    )


async def verify_admin_password(
    x_admin_password: Optional[str] = Header(None, alias="X-Admin-Password"),
) -> str:
    """FastAPI dependency to verify admin password from X-Admin-Password header.
    
    This dependency should be applied to all admin endpoints.
    Uses timing-safe comparison to prevent timing attacks.
    
    Args:
        x_admin_password: The admin password from the X-Admin-Password header.
    
    Returns:
        The admin password if valid.
    
    Raises:
        HTTPException: 401 Unauthorized if password is missing or invalid.
    """
    if not x_admin_password:
        raise HTTPException(
            status_code=401,
            detail="Invalid admin password"
        )
    
    # Check if settings are loaded
    if not settings:
        raise HTTPException(
            status_code=500,
            detail="Server configuration not loaded"
        )
    
    # Strip whitespace from both passwords before comparison
    provided_password = x_admin_password.strip()
    expected_password = settings.admin_password.strip()
    
    # Use timing-safe comparison to prevent timing attacks
    if hmac.compare_digest(provided_password, expected_password):
        return x_admin_password
    
    raise HTTPException(
        status_code=401,
        detail="Invalid admin password"
    )


# Background task for periodic saves
import asyncio
save_task: Optional[asyncio.Task] = None


async def periodic_save():
    """Background task that saves analytics every 5 minutes."""
    while True:
        await asyncio.sleep(300)  # 5 minutes
        try:
            # The database auto-persists, but we log for visibility
            print("[Auto-Save] Analytics persisted to database")
        except Exception as e:
            print(f"[Auto-Save] Error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - startup and shutdown."""
    global db, settings, save_task, http_client
    
    # Startup: Initialize database and settings
    try:
        settings = load_settings()
    except ValueError:
        # For testing, use defaults
        settings = None
    
    # Initialize database (auto-detects SQLite vs PostgreSQL)
    if settings and settings.database_url:
        print(f"✓ Using PostgreSQL database")
        db = create_database(database_url=settings.database_url)
    else:
        db_path = settings.database_path if settings else "./proxy.db"
        print(f"✓ Using SQLite database: {db_path}")
        db = create_database(database_path=db_path)
    
    await db.initialize()
    
    # Initialize global HTTP client with connection pooling for 100+ concurrent users
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=15.0,      # Connection timeout
            read=600.0,        # Read timeout (10 min for long AI responses)
            write=60.0,        # Write timeout
            pool=30.0          # Pool timeout
        ),
        limits=httpx.Limits(
            max_keepalive_connections=100,  # Keep 100 connections alive
            max_connections=200,            # Allow up to 200 total connections
            keepalive_expiry=120.0          # Keep connections alive for 2 minutes
        ),
        http2=False,  # Use HTTP/1.1 for better compatibility
    )
    print("✓ Initialized HTTP client (100 keepalive, 200 max connections)")
    
    # Load existing data on startup
    keys = await db.get_all_keys()
    print(f"✓ Loaded {len(keys)} API keys from database")
    
    config = await db.get_config()
    if config:
        print(f"✓ Loaded proxy config from database")
    
    banned = await db.get_all_banned_ips()
    print(f"✓ Loaded {len(banned)} banned IPs from database")
    
    # Start periodic save task
    save_task = asyncio.create_task(periodic_save())
    print("✓ Started periodic auto-save (every 5 minutes)")
    
    yield
    
    # Shutdown: Cancel save task, close HTTP client, and close database
    if save_task:
        save_task.cancel()
        try:
            await save_task
        except asyncio.CancelledError:
            pass
    
    if http_client:
        await http_client.aclose()
        print("✓ HTTP client closed")
    
    if db:
        await db.close()
        print("✓ Database connection closed")


app = FastAPI(
    title="AI Proxy",
    description="OpenAI-compatible API proxy with Google OAuth key generation",
    version="1.0.0",
    lifespan=lifespan,
)

# ==================== Session Middleware (for OAuth) ====================
# max_age=1 year so login persists across browser restarts; https_only=False so HTTP (localhost) works
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=60 * 60 * 24 * 365,
    https_only=False,
    same_site="lax",
)

# ==================== CORS Configuration ====================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)


# ==================== Cache Control Middleware ====================

class NoCacheMiddleware(BaseHTTPMiddleware):
    """Middleware to add no-cache headers to admin API responses.
    
    This prevents Cloudflare and browsers from caching admin API responses,
    ensuring the dashboard always shows fresh data.
    """
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Add no-cache headers to admin API endpoints
        if request.url.path.startswith("/admin/") or request.url.path == "/admin":
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        return response


app.add_middleware(NoCacheMiddleware)

# ==================== Static File Serving ====================

# Mount static files for CSS and JS (must be before route definitions)
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ==================== Google OAuth Endpoints ====================

def _is_https(request: Request) -> bool:
    """True if the client connection is HTTPS (handles proxies via X-Forwarded-Proto)."""
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").strip().lower()
    return proto == "https"


@app.get("/auth/login")
async def google_login(request: Request):
    """Redirect to Google OAuth login."""
    redirect_uri = OAUTH_REDIRECT_URI
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback")
async def google_callback(request: Request):
    """Handle Google OAuth callback and generate/retrieve API key."""
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        
        if not user_info:
            return RedirectResponse(url="/?error=no_user_info")
        
        google_id = user_info.get('sub')  # Google's unique user ID
        google_email = user_info.get('email', '')
        
        if not google_id:
            return RedirectResponse(url="/?error=no_google_id")
        
        # Check if user already has a key
        existing_key = await db.get_key_by_google_id(google_id)
        
        if existing_key:
            # Persist in both session and cookie so at least one works (browser-dependent)
            request.session["google_id"] = google_id
            response = RedirectResponse(url=f"/?key_prefix={existing_key.key_prefix}&existing=true&email={google_email}")
            _secure = _is_https(request)
            response.set_cookie(
                key="google_id",
                value=google_id,
                path="/",
                httponly=True,
                secure=_secure,
                samesite="lax",
                max_age=60*60*24*365,  # 1 year
            )
            return response
        
        # Abuse protection: limit keys per IP
        client_ip = get_client_ip(request)
        max_keys = (settings.max_keys_per_ip if settings else 2)
        if await db.count_keys_by_ip(client_ip) >= max_keys:
            return RedirectResponse(url=f"/?error=too_many_keys&limit={max_keys}")
        
        # Generate new API key for this Google account
        api_key = generate_api_key()
        key_hash = hash_api_key(api_key)
        key_prefix = get_key_prefix(api_key)
        
        # Store in database
        await db.create_api_key(
            google_id=google_id,
            google_email=google_email,
            key_hash=key_hash,
            key_prefix=key_prefix,
            full_key=api_key,
            ip_address=client_ip,
        )
        
        # Redirect with the new key (only shown once!) — persist in session + cookie
        request.session["google_id"] = google_id
        response = RedirectResponse(url=f"/?key={api_key}&key_prefix={key_prefix}&new=true&email={google_email}")
        _secure = _is_https(request)
        response.set_cookie(
            key="google_id",
            value=google_id,
            path="/",
            httponly=True,
            secure=_secure,
            samesite="lax",
            max_age=60*60*24*365,  # 1 year
        )
        return response
        
    except Exception as e:
        print(f"[OAuth Error] {e}")
        # Don't put exception details in URL (security)
        return RedirectResponse(url="/?error=oauth_failed")


@app.get("/auth/logout")
async def logout(request: Request):
    """Clear session and cookie."""
    request.session.clear()
    response = RedirectResponse(url="/")
    response.delete_cookie("google_id", path="/", secure=_is_https(request))
    return response


@app.get("/api/me")
async def get_current_user(request: Request):
    """Get current user: session first (more reliable), then cookie."""
    google_id = request.session.get("google_id") or request.cookies.get("google_id")
    if not google_id:
        raise HTTPException(status_code=401, detail="Not logged in")
    
    key_record = await db.get_key_by_google_id(google_id)
    if not key_record:
        raise HTTPException(status_code=404, detail="No API key found")
    
    # Tokens used today (UTC day) for daily quota display
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    tokens_today = await db.get_daily_tokens_used(
        key_record.id, today_start.isoformat(), today_end.isoformat()
    )
    usage_stats = await db.get_usage_stats(key_record.id)
    
    return {
        "key_prefix": key_record.key_prefix,
        "full_key": key_record.full_key,
        "google_email": key_record.google_email,
        "enabled": key_record.enabled,
        "current_rpm": key_record.current_rpm,
        "current_rpd": tokens_today,  # tokens used today (daily quota is token-based)
        "tokens_per_day_limit": TOKENS_PER_DAY_LIMIT,
        "total_tokens": usage_stats.total_tokens,
    }


# ==================== API Key Endpoints ====================

class KeyGenerationRequest(BaseModel):
    """Request model for key generation with optional fingerprint."""
    fingerprint: Optional[str] = None


@app.post(
    "/api/generate-key",
    response_model=KeyGenerationResponse,
    responses={403: {"model": ErrorResponse}},
)
async def generate_key_endpoint(
    request: Request,
    body: Optional[KeyGenerationRequest] = None,
    client_ip: str = Depends(check_ip_ban),
) -> KeyGenerationResponse:
    """Generate a new API key for the requesting IP address.
    
    Key lookup priority:
    1. Same IP → return existing key
    2. Same fingerprint, different IP → update IP and return existing key
    3. New IP + new fingerprint → generate new key
    
    Returns:
        KeyGenerationResponse with the full key and prefix.
    """
    fingerprint = body.fingerprint if body else None
    
    # 1. Check if IP already has a key
    existing_key = await db.get_key_by_ip(client_ip)
    if existing_key:
        # Update fingerprint if provided and not set
        if fingerprint and not existing_key.browser_fingerprint:
            await db.update_key_fingerprint(existing_key.id, fingerprint)
        return KeyGenerationResponse(
            key=existing_key.full_key,  # Return full key from database
            key_prefix=existing_key.key_prefix,
            message="Your API key is shown below."
        )
    
    # 2. Check if fingerprint matches an existing key (IP changed)
    if fingerprint:
        fingerprint_key = await db.get_key_by_fingerprint(fingerprint)
        if fingerprint_key:
            # Update the IP address to the new one
            await db.update_key_ip(fingerprint_key.id, client_ip)
            return KeyGenerationResponse(
                key=fingerprint_key.full_key,  # Return full key from database
                key_prefix=fingerprint_key.key_prefix,
                message="Welcome back! Your IP changed but we recognized your browser."
            )
    
    # Abuse protection: limit keys per IP
    max_keys = (settings.max_keys_per_ip if settings else 2)
    if await db.count_keys_by_ip(client_ip) >= max_keys:
        raise HTTPException(
            status_code=403,
            detail=f"Maximum number of API keys per IP ({max_keys}) reached. Use an existing key or contact support."
        )
    
    # 3. Generate new key for new user
    new_key = generate_api_key()
    key_hash = hash_api_key(new_key)
    key_prefix = get_key_prefix(new_key)
    
    # Store in database with fingerprint AND full key
    # For IP-based key generation (legacy), use IP as a pseudo google_id
    await db.create_api_key(
        google_id=f"ip_{client_ip}",  # Use IP as pseudo Google ID for legacy support
        google_email=None,
        key_hash=key_hash,
        key_prefix=key_prefix,
        full_key=new_key,
        ip_address=client_ip,
    )
    
    # Update fingerprint if provided
    if fingerprint:
        key_record = await db.get_key_by_ip(client_ip)
        if key_record:
            await db.update_key_fingerprint(key_record.id, fingerprint)
    
    return KeyGenerationResponse(
        key=new_key,
        key_prefix=key_prefix,
        message="API key generated successfully!"
    )


@app.get(
    "/api/my-key",
    response_model=KeyInfoResponse,
    responses={403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def get_my_key(
    request: Request,
    client_ip: str = Depends(check_ip_ban),
) -> KeyInfoResponse:
    """Get information about the API key associated with the requesting IP.
    
    Returns:
        KeyInfoResponse with key metadata and current usage.
    """
    # Get key for this IP
    key_record = await db.get_key_by_ip(client_ip)
    if not key_record:
        raise HTTPException(
            status_code=404,
            detail="No API key found for your IP address"
        )
    
    # Tokens used today (UTC day) for display
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    tokens_today = await db.get_daily_tokens_used(
        key_record.id, today_start.isoformat(), today_end.isoformat()
    )
    
    return KeyInfoResponse(
        key_prefix=key_record.key_prefix,
        enabled=key_record.enabled,
        created_at=key_record.created_at.isoformat(),
        rpm_used=key_record.current_rpm,
        rpm_limit=RPM_LIMIT,
        rpd_used=tokens_today,
        rpd_limit=TOKENS_PER_DAY_LIMIT,
    )


@app.get(
    "/api/my-usage",
    response_model=UsageResponse,
    responses={403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def get_my_usage(
    request: Request,
    client_ip: str = Depends(check_ip_ban),
) -> UsageResponse:
    """Get usage statistics for the API key associated with the requesting IP.
    
    Returns:
        UsageResponse with current rate limit status and total token usage.
    """
    # Get key for this IP
    key_record = await db.get_key_by_ip(client_ip)
    if not key_record:
        raise HTTPException(
            status_code=404,
            detail="No API key found for your IP address"
        )
    
    # Check if rate limits need to be reset (without incrementing)
    now = datetime.now(timezone.utc)
    current_rpm = key_record.current_rpm
    current_rpd = key_record.current_rpd
    
    # Check if RPM needs to be reset
    last_rpm_reset = key_record.last_rpm_reset
    if last_rpm_reset.tzinfo is None:
        last_rpm_reset = last_rpm_reset.replace(tzinfo=timezone.utc)
    
    if (now - last_rpm_reset).total_seconds() >= RPM_WINDOW_SECONDS:
        await db.reset_rpm(key_record.id)
        current_rpm = 0
    
    # Check if RPD needs to be reset
    last_rpd_reset = key_record.last_rpd_reset
    if last_rpd_reset.tzinfo is None:
        last_rpd_reset = last_rpd_reset.replace(tzinfo=timezone.utc)
    
    if now.date() > last_rpd_reset.date():
        await db.reset_rpd(key_record.id)
        current_rpd = 0
    
    # Tokens used today (UTC day) for daily quota display
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    tokens_today = await db.get_daily_tokens_used(
        key_record.id, today_start.isoformat(), today_end.isoformat()
    )
    
    usage_stats = await db.get_usage_stats(key_record.id)
    
    return UsageResponse(
        rpm_used=current_rpm,
        rpm_limit=RPM_LIMIT,
        rpm_remaining=max(0, RPM_LIMIT - current_rpm),
        rpd_used=tokens_today,
        rpd_limit=TOKENS_PER_DAY_LIMIT,
        rpd_remaining=max(0, TOKENS_PER_DAY_LIMIT - tokens_today),
        total_tokens=usage_stats.total_tokens,
    )


# ==================== Proxy Endpoints ====================

@app.get("/v1/models")
async def proxy_models(
    request: Request,
    key_data: Tuple[ApiKeyRecord, str] = Depends(validate_api_key),
):
    """Proxy the /v1/models endpoint to the target API.
    
    Lists available models from the target API.
    Note: This endpoint does NOT count against rate limits.
    
    Returns:
        The models list from the target API.
    """
    key_record, client_ip = key_data
    
    # NOTE: /v1/models does NOT count against rate limits
    # It's just listing available models, not making actual API calls
    
    # Get target API config
    target_url, target_key = await get_target_api_config()
    
    # Forward request to target API using global client
    try:
        response = await http_client.get(
            f"{target_url}/models",
            headers={"Authorization": f"Bearer {target_key}"},
        )
        
        # Log usage (0 tokens for models endpoint, doesn't affect rate limits)
        await db.log_usage(
            key_id=key_record.id,
            model="models",
            tokens=0,
            success=response.status_code == 200,
            ip_address=client_ip,
        )
        
        try:
            content = response.json()
        except Exception:
            content = {"error": {"message": "Upstream returned invalid JSON"}}
        return JSONResponse(
            status_code=response.status_code,
            content=content,
        )
    except httpx.TimeoutException:
        await db.log_usage(
            key_id=key_record.id,
            model="models",
            tokens=0,
            success=False,
            ip_address=client_ip,
            error_message="Upstream API timeout",
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to reach upstream API"
        )
    except httpx.RequestError as e:
        await db.log_usage(
            key_id=key_record.id,
            model="models",
            tokens=0,
            success=False,
            ip_address=client_ip,
            error_message=str(e),
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to reach upstream API"
        )


@app.post("/v1/chat/completions")
async def proxy_chat_completions(
    request: Request,
    chat_request: ChatCompletionRequest,
    key_data: Tuple[ApiKeyRecord, str] = Depends(validate_api_key),
):
    """Proxy the /v1/chat/completions endpoint to the target API.
    
    Forwards chat completion requests to the target API, handling both
    streaming and non-streaming responses.
    
    Args:
        request: The FastAPI request object.
        chat_request: The chat completion request body.
        key_data: Validated API key and client IP from dependency.
    
    Returns:
        The chat completion response from the target API.
    """
    key_record, client_ip = key_data
    
    # Check rate limits (pass estimated tokens for daily token quota)
    estimated_tokens = token_count + (await get_max_output_tokens())
    rate_result = await check_and_update_rate_limits(key_record, db, estimated_tokens=estimated_tokens)
    if not rate_result.allowed:
        return create_rate_limit_response(rate_result)
    
    # Check max context limit
    token_count = count_tokens(chat_request.messages)
    max_context = await get_max_context()
    
    if token_count > max_context:
        raise HTTPException(
            status_code=400,
            detail=f"Request exceeds maximum context limit of {max_context} tokens"
        )
    
    # Get target API config
    target_url, target_key = await get_target_api_config()
    
    # Prepare request body
    request_body = chat_request.model_dump(exclude_none=True)
    
    # Cap max_tokens (output limit) to prevent long completions draining quota
    max_out = await get_max_output_tokens()
    requested_max = request_body.get("max_tokens")
    request_body["max_tokens"] = min(requested_max or max_out, max_out)
    
    # Log the request for debugging
    print(f"[Proxy Request] Model: {request_body.get('model')}, Stream: {request_body.get('stream')}, Target: {target_url}")
    
    # Handle streaming response
    if chat_request.stream:
        return await _handle_streaming_request(
            target_url=target_url,
            target_key=target_key,
            request_body=request_body,
            key_record=key_record,
            token_count=token_count,
            client_ip=client_ip,
        )
    
    # Handle non-streaming response
    return await _handle_non_streaming_request(
        target_url=target_url,
        target_key=target_key,
        request_body=request_body,
        key_record=key_record,
        token_count=token_count,
        client_ip=client_ip,
    )


async def _handle_streaming_request(
    target_url: str,
    target_key: str,
    request_body: dict,
    key_record: ApiKeyRecord,
    token_count: int,
    client_ip: str,
) -> StreamingResponse:
    """Handle a streaming chat completion request with TPS rate limiting.
    
    Implements true streaming - forwards chunks immediately from upstream.
    Rate limits output to MAX_TOKENS_PER_SECOND (35 TPS) to prevent overwhelming clients.
    
    Args:
        target_url: The target API URL.
        target_key: The target API key.
        request_body: The request body to forward.
        key_record: The API key record.
        token_count: Estimated token count for logging.
        client_ip: The client's IP address.
    
    Returns:
        StreamingResponse that forwards the target API's stream.
    """
    import json as json_module
    import time
    
    async def stream_generator() -> AsyncGenerator[bytes, None]:
        output_tokens = 0
        total_tokens = token_count
        input_tokens_actual = token_count
        stream_success = False
        error_message = None
        
        # TPS rate limiting state
        tokens_this_second = 0
        last_second = time.monotonic()
        
        try:
            # Use global client for connection reuse
            async with http_client.stream(
                "POST",
                f"{target_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {target_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                },
                json=request_body,
            ) as response:
                stream_success = response.status_code == 200
                
                # If non-200 response, forward error immediately
                if not stream_success:
                    error_body = await response.aread()
                    error_text = error_body.decode('utf-8', errors='replace')
                    
                    # Log the full error for debugging
                    print(f"[Upstream Error] Status: {response.status_code}, Body: {error_text[:500]}")
                    
                    try:
                        error_data = json_module.loads(error_text)
                        error_message = error_data.get('error', {}).get('message') or error_data.get('detail') or error_text
                    except (json_module.JSONDecodeError, TypeError):
                        error_message = error_text or f"Upstream returned {response.status_code}"
                    
                    await db.log_usage(
                        key_id=key_record.id,
                        model=request_body.get("model", "unknown"),
                        tokens=token_count,
                        success=False,
                        ip_address=client_ip,
                        input_tokens=token_count,
                        output_tokens=0,
                        error_message=error_message[:500],  # Truncate for DB
                    )
                    
                    # Return error in SSE format so clients can parse it
                    error_response = {
                        "error": {
                            "message": error_message,
                            "type": "upstream_error",
                            "code": response.status_code
                        }
                    }
                    yield f"data: {json_module.dumps(error_response)}\n\n".encode('utf-8')
                    yield b"data: [DONE]\n\n"
                    return
                
                # True streaming - forward each chunk immediately
                async for chunk in response.aiter_bytes():
                    # Count tokens in this chunk for TPS limiting
                    chunk_tokens = 0
                    try:
                        chunk_str = chunk.decode('utf-8')
                        for line in chunk_str.split('\n'):
                            if line.startswith('data: ') and line != 'data: [DONE]':
                                data_str = line[6:]
                                if data_str.strip():
                                    try:
                                        data = json_module.loads(data_str)
                                        # Count tokens from delta content
                                        if 'choices' in data:
                                            for choice in data['choices']:
                                                delta = choice.get('delta', {})
                                                content = delta.get('content', '')
                                                if content:
                                                    # Rough estimate: 1 token ≈ 4 chars
                                                    chunk_tokens += max(1, len(content) // 4)
                                        # Extract final usage stats
                                        if 'usage' in data:
                                            input_tokens_actual = data['usage'].get('prompt_tokens', token_count)
                                            output_tokens = data['usage'].get('completion_tokens', 0)
                                            total_tokens = data['usage'].get('total_tokens', token_count)
                                        if 'error' in data:
                                            error_message = data['error'].get('message') or str(data['error'])
                                            stream_success = False
                                    except json_module.JSONDecodeError:
                                        pass
                    except UnicodeDecodeError:
                        chunk_tokens = 1  # Assume at least 1 token for binary chunks
                    
                    # TPS rate limiting - only throttle if we're going too fast
                    current_time = time.monotonic()
                    if current_time - last_second >= 1.0:
                        # New second, reset counter
                        tokens_this_second = 0
                        last_second = current_time
                    
                    tokens_this_second += max(1, chunk_tokens)
                    
                    # If we've exceeded TPS limit, add a small delay
                    if tokens_this_second > MAX_TOKENS_PER_SECOND:
                        # Calculate how long to wait
                        wait_time = 1.0 - (current_time - last_second)
                        if wait_time > 0:
                            await asyncio.sleep(wait_time)
                        tokens_this_second = max(1, chunk_tokens)
                        last_second = time.monotonic()
                    
                    # Yield chunk immediately (true streaming)
                    yield chunk
                
                # Log usage after stream completes
                await db.log_usage(
                    key_id=key_record.id,
                    model=request_body.get("model", "unknown"),
                    tokens=total_tokens,
                    success=stream_success,
                    ip_address=client_ip,
                    input_tokens=input_tokens_actual,
                    output_tokens=output_tokens,
                    error_message=error_message,
                )
        except httpx.TimeoutException as e:
            print(f"[Upstream Timeout] {str(e)}")
            await db.log_usage(
                key_id=key_record.id,
                model=request_body.get("model", "unknown"),
                tokens=token_count,
                success=False,
                ip_address=client_ip,
                input_tokens=token_count,
                error_message="Upstream API timeout",
            )
            error_response = {"error": {"message": "Upstream API timeout", "type": "timeout", "code": 504}}
            yield f"data: {json_module.dumps(error_response)}\n\n".encode('utf-8')
            yield b"data: [DONE]\n\n"
        except httpx.RequestError as e:
            print(f"[Upstream Request Error] {str(e)}")
            await db.log_usage(
                key_id=key_record.id,
                model=request_body.get("model", "unknown"),
                tokens=token_count,
                success=False,
                ip_address=client_ip,
                input_tokens=token_count,
                error_message=str(e),
            )
            error_response = {"error": {"message": f"Unable to reach upstream API: {str(e)}", "type": "connection_error", "code": 502}}
            yield f"data: {json_module.dumps(error_response)}\n\n".encode('utf-8')
            yield b"data: [DONE]\n\n"
    
    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx/proxy buffering
        }
    )


async def _handle_non_streaming_request(
    target_url: str,
    target_key: str,
    request_body: dict,
    key_record: ApiKeyRecord,
    token_count: int,
    client_ip: str,
) -> JSONResponse:
    """Handle a non-streaming chat completion request.
    
    Uses the global HTTP client for connection reuse and optimal performance.
    
    Args:
        target_url: The target API URL.
        target_key: The target API key.
        request_body: The request body to forward.
        key_record: The API key record.
        token_count: Estimated token count for logging.
        client_ip: The client's IP address.
    
    Returns:
        JSONResponse with the target API's response.
    """
    try:
        # Use global client for connection reuse
        response = await http_client.post(
            f"{target_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {target_key}",
                "Content-Type": "application/json",
            },
            json=request_body,
        )
        
        response_data = response.json()
        
        # Extract actual token usage if available
        input_tokens = token_count
        output_tokens = 0
        actual_tokens = token_count
        if "usage" in response_data:
            input_tokens = response_data["usage"].get("prompt_tokens", token_count)
            output_tokens = response_data["usage"].get("completion_tokens", 0)
            actual_tokens = response_data["usage"].get("total_tokens", token_count)
        
        # Log usage
        await db.log_usage(
            key_id=key_record.id,
            model=request_body.get("model", "unknown"),
            tokens=actual_tokens,
            success=response.status_code == 200,
            ip_address=client_ip,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        
        return JSONResponse(
            status_code=response.status_code,
            content=response_data,
        )
    except httpx.TimeoutException:
        await db.log_usage(
            key_id=key_record.id,
            model=request_body.get("model", "unknown"),
            tokens=token_count,
            success=False,
            ip_address=client_ip,
            input_tokens=token_count,
            error_message="Upstream API timeout",
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to reach upstream API"
        )
    except httpx.RequestError as e:
        await db.log_usage(
            key_id=key_record.id,
            model=request_body.get("model", "unknown"),
            tokens=token_count,
            success=False,
            ip_address=client_ip,
            input_tokens=token_count,
            error_message=str(e),
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to reach upstream API"
        )


# ==================== Admin Endpoints ====================

@app.get(
    "/admin/keys",
    response_model=list[AdminKeyResponse],
    responses={401: {"model": ErrorResponse}},
)
async def admin_list_keys(
    _: str = Depends(verify_admin_password),
) -> list[AdminKeyResponse]:
    """List all API keys with their metadata.
    
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        List of all API keys with metadata.
    """
    def _ts_str(val):
        """Serialize timestamp to string (handles datetime or str from DB)."""
        if val is None:
            return None
        if hasattr(val, "isoformat"):
            return val.isoformat()
        return str(val)

    keys = await db.get_all_keys()
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    result = []
    for key in keys:
        try:
            tokens_today = await db.get_daily_tokens_used(
                key.id, today_start.isoformat(), today_end.isoformat()
            )
            result.append(AdminKeyResponse(
                id=key.id,
                key_prefix=key.key_prefix or "",
                ip_address=key.ip_address or "",
                google_email=key.google_email,
                enabled=key.enabled,
                bypass_ip_ban=getattr(key, "bypass_ip_ban", False),
                current_rpm=key.current_rpm,
                current_rpd=key.current_rpd,
                tokens_used_today=tokens_today,
                created_at=_ts_str(key.created_at),
                last_used_at=_ts_str(key.last_used_at),
            ))
        except Exception as e:
            print(f"[Admin] Skipping key {getattr(key, 'id', '?')}: {e}")
            continue
    return result


@app.put(
    "/admin/keys/{key_id}/bypass-ip",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_set_key_bypass_ip(
    key_id: int,
    body: BypassIpRequest,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Set whether this API key bypasses IP ban checks.
    
    When bypass is True, requests with this key are allowed even from banned IPs.
    Requires admin authentication via X-Admin-Password header.
    """
    updated = await db.set_key_bypass_ip_ban(key_id, body.bypass)
    if not updated:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"message": f"IP bypass {'enabled' if body.bypass else 'disabled'} for this key", "bypass": body.bypass}


@app.delete(
    "/admin/keys/{key_id}",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_delete_key(
    key_id: int,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Delete an API key by ID.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        key_id: The ID of the key to delete.
    
    Returns:
        Success message.
    """
    deleted = await db.delete_key(key_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="API key not found"
        )
    return {"message": "API key deleted successfully"}


@app.put(
    "/admin/keys/{key_id}/toggle",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_toggle_key(
    key_id: int,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Toggle the enabled status of an API key.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        key_id: The ID of the key to toggle.
    
    Returns:
        Success message.
    """
    toggled = await db.toggle_key(key_id)
    if not toggled:
        raise HTTPException(
            status_code=404,
            detail="API key not found"
        )
    return {"message": "API key toggled successfully"}


@app.get(
    "/admin/config",
    response_model=ConfigResponse,
    responses={401: {"model": ErrorResponse}},
)
async def admin_get_config(
    _: str = Depends(verify_admin_password),
) -> ConfigResponse:
    """Get the current proxy configuration.
    
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        Current proxy configuration with masked API key.
    """
    config = await db.get_config()
    
    if config:
        # Mask the API key (show first 8 and last 4 characters)
        key = config.target_api_key
        if len(key) > 12:
            masked_key = f"{key[:8]}...{key[-4:]}"
        else:
            masked_key = "***"
        
        return ConfigResponse(
            target_api_url=config.target_api_url,
            target_api_key_masked=masked_key,
            max_context=config.max_context,
            max_output_tokens=config.max_output_tokens,
            max_keys_per_ip=settings.max_keys_per_ip if settings else 2,
        )
    
    # Fall back to settings
    if settings:
        key = settings.target_api_key
        if len(key) > 12:
            masked_key = f"{key[:8]}...{key[-4:]}"
        else:
            masked_key = "***"
        
        return ConfigResponse(
            target_api_url=settings.target_api_url,
            target_api_key_masked=masked_key,
            max_context=settings.max_context,
            max_output_tokens=settings.max_output_tokens,
            max_keys_per_ip=settings.max_keys_per_ip,
        )
    
    raise HTTPException(
        status_code=500,
        detail="Proxy not configured"
    )


@app.put(
    "/admin/config",
    responses={401: {"model": ErrorResponse}},
)
async def admin_update_config(
    config_update: ConfigUpdateRequest,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Update the proxy configuration.
    
    Requires admin authentication via X-Admin-Password header.
    Only provided fields will be updated.
    
    Args:
        config_update: The configuration fields to update.
    
    Returns:
        Success message.
    """
    # Get current config
    current_config = await db.get_config()
    
    if current_config:
        target_url = config_update.target_api_url or current_config.target_api_url
        target_key = config_update.target_api_key or current_config.target_api_key
        max_context = config_update.max_context if config_update.max_context is not None else current_config.max_context
        max_output_tokens = config_update.max_output_tokens if config_update.max_output_tokens is not None else current_config.max_output_tokens
    elif settings:
        target_url = config_update.target_api_url or settings.target_api_url
        target_key = config_update.target_api_key or settings.target_api_key
        max_context = config_update.max_context if config_update.max_context is not None else settings.max_context
        max_output_tokens = config_update.max_output_tokens if config_update.max_output_tokens is not None else settings.max_output_tokens
    else:
        raise HTTPException(
            status_code=500,
            detail="Proxy not configured"
        )
    
    await db.update_config(target_url, target_key, max_context, max_output_tokens)
    return {"message": "Configuration updated successfully"}


@app.get(
    "/admin/banned-ips",
    response_model=list[BannedIpResponse],
    responses={401: {"model": ErrorResponse}},
)
async def admin_list_banned_ips(
    _: str = Depends(verify_admin_password),
) -> list[BannedIpResponse]:
    """List all banned IP addresses.
    
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        List of all banned IPs with metadata.
    """
    banned_ips = await db.get_all_banned_ips()
    return [
        BannedIpResponse(
            id=ip.id,
            ip_address=ip.ip_address,
            reason=ip.reason,
            banned_at=ip.banned_at.isoformat(),
        )
        for ip in banned_ips
    ]


@app.post(
    "/admin/ban-ip",
    responses={401: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def admin_ban_ip(
    ban_request: BanIpRequest,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Ban an IP address.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        ban_request: The IP address to ban and optional reason.
    
    Returns:
        Success message.
    """
    import ipaddress
    
    # Validate IP address format
    try:
        ipaddress.ip_address(ban_request.ip_address)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address format"
        )
    
    await db.ban_ip(ban_request.ip_address, ban_request.reason)
    return {"message": f"IP address {ban_request.ip_address} has been banned"}


@app.delete(
    "/admin/ban-ip/{ip_address:path}",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_unban_ip(
    ip_address: str,
    _: str = Depends(verify_admin_password),
) -> dict:
    """Unban an IP address.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        ip_address: The IP address to unban.
    
    Returns:
        Success message.
    """
    unbanned = await db.unban_ip(ip_address)
    if not unbanned:
        raise HTTPException(
            status_code=404,
            detail="IP address not found in ban list"
        )
    return {"message": f"IP address {ip_address} has been unbanned"}


@app.post(
    "/admin/reset-all-rpd",
    responses={401: {"model": ErrorResponse}},
)
async def admin_reset_all_rpd(
    _: str = Depends(verify_admin_password),
) -> dict:
    """Reset RPD (requests per day) counters for all API keys.
    
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        Success message with count of reset keys.
    """
    count = await db.reset_all_rpd()
    return {"message": f"Reset RPD counters for {count} API keys", "count": count}


@app.post(
    "/admin/reset-all-rpm",
    responses={401: {"model": ErrorResponse}},
)
async def admin_reset_all_rpm(
    _: str = Depends(verify_admin_password),
) -> dict:
    """Reset RPM (requests per minute) counters for all API keys.
    
    Requires admin authentication via X-Admin-Password header.
    
    Returns:
        Success message with count of reset keys.
    """
    count = await db.reset_all_rpm()
    return {"message": f"Reset RPM counters for {count} API keys", "count": count}


@app.get(
    "/admin/request-logs",
    response_model=list[RequestLogResponse],
    responses={401: {"model": ErrorResponse}},
)
async def admin_get_request_logs(
    limit: int = 10,
    _: str = Depends(verify_admin_password),
) -> list[RequestLogResponse]:
    """Get recent request logs across all API keys.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        limit: Maximum number of logs to return (default 10).
    
    Returns:
        List of recent request logs.
    """
    logs = await db.get_recent_requests(limit=min(limit, 100))
    return [
        RequestLogResponse(
            id=log.id,
            key_prefix=log.key_prefix,
            ip_address=log.ip_address,
            model=log.model,
            input_tokens=log.input_tokens,
            output_tokens=log.output_tokens,
            total_tokens=log.total_tokens,
            success=log.success,
            error_message=log.error_message,
            request_time=log.request_time.isoformat(),
        )
        for log in logs
    ]


@app.get(
    "/admin/top-requests",
    response_model=list[RequestLogResponse],
    responses={401: {"model": ErrorResponse}},
)
async def admin_get_top_requests(
    limit: int = 3,
    _: str = Depends(verify_admin_password),
) -> list[RequestLogResponse]:
    """Get requests with highest token usage.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        limit: Maximum number of logs to return (default 3).
    
    Returns:
        List of top token usage requests.
    """
    logs = await db.get_top_token_requests(limit=min(limit, 10))
    return [
        RequestLogResponse(
            id=log.id,
            key_prefix=log.key_prefix,
            ip_address=log.ip_address,
            model=log.model,
            input_tokens=log.input_tokens,
            output_tokens=log.output_tokens,
            total_tokens=log.total_tokens,
            success=log.success,
            error_message=log.error_message,
            request_time=log.request_time.isoformat(),
        )
        for log in logs
    ]


@app.get(
    "/admin/keys/{key_id}/analytics",
    response_model=KeyAnalyticsResponse,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def admin_get_key_analytics(
    key_id: int,
    _: str = Depends(verify_admin_password),
) -> KeyAnalyticsResponse:
    """Get detailed analytics for a specific API key.
    
    Requires admin authentication via X-Admin-Password header.
    
    Args:
        key_id: The ID of the key to get analytics for.
    
    Returns:
        Detailed analytics including usage stats and recent requests.
    """
    analytics = await db.get_key_analytics(key_id)
    if not analytics:
        raise HTTPException(
            status_code=404,
            detail="API key not found"
        )
    
    return KeyAnalyticsResponse(
        key_id=analytics.key_id,
        key_prefix=analytics.key_prefix,
        ip_address=analytics.ip_address,
        total_input_tokens=analytics.total_input_tokens,
        total_output_tokens=analytics.total_output_tokens,
        total_tokens=analytics.total_tokens,
        total_requests=analytics.total_requests,
        successful_requests=analytics.successful_requests,
        most_used_model=analytics.most_used_model,
        model_usage_count=analytics.model_usage_count,
        recent_requests=[
            RequestLogResponse(
                id=req.id,
                key_prefix=req.key_prefix,
                ip_address=req.ip_address,
                model=req.model,
                input_tokens=req.input_tokens,
                output_tokens=req.output_tokens,
                total_tokens=req.total_tokens,
                success=req.success,
                error_message=req.error_message,
                request_time=req.request_time.isoformat(),
            )
            for req in analytics.recent_requests
        ],
    )


# ==================== Debug Endpoint ====================

@app.get("/debug/ip", include_in_schema=False)
async def debug_ip(request: Request):
    """Debug endpoint to see what IP headers Zeabur is sending.
    
    Returns all relevant headers and the detected client IP.
    """
    headers_to_check = [
        "CF-Connecting-IP",
        "X-Real-IP", 
        "X-Forwarded-For",
        "True-Client-IP",
        "X-Client-IP",
        "X-Original-Forwarded-For",
    ]
    
    found_headers = {}
    for header in headers_to_check:
        value = request.headers.get(header)
        if value:
            found_headers[header] = value
    
    return {
        "detected_ip": get_client_ip(request),
        "direct_client": request.client.host if request.client else None,
        "proxy_headers": found_headers,
        "all_headers": dict(request.headers),
    }


# ==================== Frontend Routes ====================

@app.get("/", include_in_schema=False)
async def serve_index():
    """Serve the public frontend index.html.
    
    Returns:
        The index.html file for the public frontend.
    """
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path), media_type="text/html")
    # Debug info for troubleshooting
    raise HTTPException(
        status_code=404, 
        detail=f"Frontend not found. Checked: {FRONTEND_DIR}, exists={FRONTEND_DIR.exists()}, cwd={Path.cwd()}"
    )


@app.get("/admin", include_in_schema=False)
async def serve_admin():
    """Serve the admin dashboard admin.html.
    
    Returns:
        The admin.html file for the admin dashboard.
    """
    admin_path = FRONTEND_DIR / "admin.html"
    if admin_path.exists():
        return FileResponse(str(admin_path), media_type="text/html")
    raise HTTPException(status_code=404, detail="Admin dashboard not found")
