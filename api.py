from psycopg2.sql import NULL
import logging, json , hashlib
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, UploadFile, File, HTTPException, Request, Header, status, Depends
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from utils.helpers import (
    get_llm_config,
    update_env_variable,
    run_analysis,
    normalize_analysis_result,
    format_analysis,
)
from utils.log_parser import read_uploaded_file
from utils.db import init_database, close_database , get_database

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_MAX_INPUT_CHARS = 10_485_760

# FastAPI APIRouter initialization
router = APIRouter()

# ==================== Helper functions ==================================

def _build_entries_payload(result: dict) -> list[dict]:
    # ASSUMPTION — verify these key names against the real shape returned
    # by normalize_analysis_result(). Same caveat as before: if these are
    # wrong, you get empty/None summaries stored successfully rather than
    # a loud failure.
    entries = result.get("classified_entries", []) or []
    payload = []
    for idx, entry in enumerate(entries, start=1):
        raw_sev = str(entry.get("severity") or "info").strip().lower()
        payload.append({
            "sequence_no": idx,
            "severity": raw_sev if raw_sev in _VALID_SEVERITIES else "info",
            "component": entry.get("component") or entry.get("source"),
            "event_time": entry.get("time") or entry.get("timestamp") or entry.get("event_time"),
            "summary": entry.get("summary") or "",
            "raw_excerpt": entry.get("raw") or entry.get("raw_excerpt"),
        })
    return payload


def _build_remediations_payload(result: dict) -> list[dict]:
    remediations = result.get("remediations", []) or []
    payload = []
    for idx, rem in enumerate(remediations, start=1):
        payload.append({
            "sequence_no": idx,
            "entry_sequence_no": rem.get("entry_index") or rem.get("entry_sequence_no"),
            "root_cause": rem.get("root_cause") or rem.get("summary") or "",
            "confidence": rem.get("confidence"),
            "fix_steps": rem.get("fix_steps") or rem.get("steps") or [],
        })
    return payload

def _resolve_requested_by(cursor, username: Optional[str]) -> Optional[str]:
    # 'admin' as a literal string is not a UUID — this resolves it to the
    # real ai_users.id. This is a stopgap, NOT authentication: it trusts
    # whatever username string shows up in the request. Replace with a
    # real auth dependency (session/JWT) that identifies the actual caller
    # — nothing in the pasted code establishes who's really calling this.
    if not username:
        return None
    cursor.execute("SELECT id FROM ai_users WHERE username = %s", (username,))
    row = cursor.fetchone()
    return str(row[0]) if row else None

async def get_current_username(authorization:Optional[str] = Header(None)) -> str:
    """
    Verifies the caller's session token against ai_sessions via
    fn_validate_session(), then resolves the username from ai_users.

    Expects: Authorization: Bearer <raw-session-token>

    ASSUMPTION, needs your confirmation: the raw token is hashed here with
    SHA-256 before being sent to fn_validate_session. That has to match
    EXACTLY the hashing scheme your login flow used when it called
    fn_create_session() to issue the token in the first place — if login
    hashes with something else (bcrypt, a salted scheme, a different
    encoding), this will never match and every request will 401. I'm
    assuming plain SHA-256 over the raw UTF-8 token because that's what I
    recommended when we built fn_create_session/ai_api_tokens earlier in
    this conversation — confirm your actual login code does the same.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = authorization.removeprefix("Bearer ").strip()
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).digest()

    db = get_database()
    conn = db.get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to acquire database connection")

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM fn_validate_session(%s)", (token_hash,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid, expired, or revoked session",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            user_id = row[0]  # fn_validate_session returns (user_id, session_id)

            cursor.execute(
                "SELECT username FROM ai_users WHERE id = %s AND status = 'active'",
                (user_id,),
            )
            user_row = cursor.fetchone()
            if not user_row:
                raise HTTPException(status_code=401, detail="User account is not active")

            return user_row[0]
    finally:
        db.return_connection(conn)

# ==================== Pydantic Models (Base Classes) ====================

class HistoryRequest(BaseModel):
    """Request model for fetching history."""
    user: Optional[str] = None
    status: Optional[str] = None
    limit: int = 50
    offset: int = 0

    class Config:
        schema_extra = {
            "example": {
                "user": "admin",
                "status": "completed",
                "limit": 50,
                "offset": 0
            }   
        }

class HistoryRequestWithParameters(BaseModel):
    """Request model for fetching history with parameters."""
    status: Optional[str] = 'In Progress'
    engine_model_id: Optional[str] = None
    analysis_code: Optional[str] = None
    content_query: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "status": "In Progress",
                "engine_model_id": "model_id",
                "analysis_code": "completed",
                "content_query": "Out of Memory"
            }   
        }   

class AnalysisRequest(BaseModel):
    """Request model for log analysis via API."""
    logs: str
    description: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "logs": "2026-05-10T10:23:45Z ERROR OOM killed process\n2026-05-10T10:24:12Z WARN High memory usage",
                "description": "Kubernetes cluster logs"
            }
        }


class AnalysisRequestWithModel(BaseModel):
    """Request model for log analysis via API."""
    id: Optional[str] = None
    timestamp: Optional[str] = None
    logs: str
    description: Optional[str] = None
    model_name: Optional[str] = "openai/gpt-4o"
    user: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "id": "ANL-1234567890",
                "timestamp": "2026-05-10T10:23:45Z",
                "logs": "2026-05-10T10:23:45Z ERROR OOM killed process\n2026-05-10T10:24:12Z WARN High memory usage",
                "description": "Kubernetes cluster logs",
                "model_name": "openai/gpt-4o",
                "user": "admin"
            }
        }

class LLMModelUpdateRequest(BaseModel):
    """Request model for updating the LLM model in .env."""
    model: str

    class Config:
        schema_extra = {
            "example": {
                "model": "openai/gpt-4o"
            }
        }


class SecureValidateUser(BaseModel):
    """Request model for validating user."""
    username: str
    password: str
    ipaddress: Optional[str] = None
    user_agent: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "username": "admin",
                "password": "password",
                "ipaddress": "[IP_ADDRESS]",
                "user_agent": "Mozilla/5.0"
            }
        }


class InsertUser(BaseModel):
    """Request model for inserting user."""
    name: str = "Full name"
    username: str = "username"
    password: str = "password"
    role: str = "user role"
    
    class Config:
        schema_extra = {
            "example": {
                "name": "John Doe",
                "username": "johndoe",
                "password": "password",
                "role": "user"
            }
        }


class AddAgentRequest(BaseModel):
    """Request model for adding a new agent."""
    name: str
    llm_model: str
    temperature: float = 0.2   
    conn_url: str
    api_key: str = 'skprj-xxxxxxxx'
    is_primary: bool = False
    is_active: bool = True

    class Config:
        schema_extra = {
            "example": {
                "name": "log_classifier_agent",
                "llm_model": "anthropic/claude-sonnet-4.5",
                "temperature": 0.2,  
                "conn_url": "https://api.example.com",
                "api_key": "",
                "is_primary": False,
                "is_active": True
            }
        }


class UpdateAgentRequest(BaseModel):
    """Request model for updating an existing agent."""
    agent_id: int
    name: str
    llm_model: str
    temperature: float = 0.2   
    conn_url: str
    api_key: str = 'skprj-xxxxxxxx'
    is_primary: bool = False
    is_active: bool = False

    class Config:
        schema_extra = {
            "example": {
                "agent_id": 1,
                "name": "log_classifier_agent",
                "llm_model": "anthropic/claude-sonnet-4.5",
                "temperature": 0.2,  
                "conn_url": "https://api.example.com",
                "api_key": "",
                "is_primary": False,
                "is_active": False
            }
        }


class deleteAgentRequest(BaseModel):
    """Request model for deleting an existing agent."""
    agent_id: int
    name: str
    
    class Config:
        schema_extra = {
            "example": {
                "agent_id": 1,
                "name": "agent1"
            }
        }   


class LogEntry(BaseModel):
    """Response model for classified log entries."""
    timestamp: str
    severity: str
    category: str
    source: str
    raw_line: str
    summary: str


class RemediationResponse(BaseModel):
    """Response model for remediation suggestions."""
    issue_summary: str
    root_cause: str
    fix_steps: list[str]
    rationale: str
    confidence: float
    linked_log_entries: list[int]


class AnalysisResponse(BaseModel):
    """Response model for complete analysis."""
    classified_entries: list[LogEntry] = []
    remediations: list[RemediationResponse] = []
    pretty_output: str = ""
    status: str = "completed"
    message: str = "Analysis completed successfully"

    class Config:
        schema_extra = {
            "example": {
                "classified_entries": [
                    {
                        "timestamp": "2026-05-10T10:23:45Z",
                        "severity": "CRITICAL",
                        "category": "OOM",
                        "source": "kubernetes",
                        "raw_line": "OOM killed process",
                        "summary": "Out of memory error detected"
                    }
                ],
                "remediations": [
                    {
                        "issue_summary": "Memory leak in application",
                        "root_cause": "Unbounded cache growth",
                        "fix_steps": ["Implement cache eviction", "Add memory limits"],
                        "rationale": "Cache was consuming all available memory",
                        "confidence": 0.95,
                        "linked_log_entries": [0]
                    }
                ],
                "status": "completed",
                "message": "Analysis completed successfully"
            }
        }


# ==================== FastAPI Endpoints ====================

@router.get("/")
def root():
    """Root endpoint with API information."""
    return {
        "service": "Sentry Incident Analyzer",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/api/health"
    }


@router.get("/api/health")
def health_check():
    """Health check endpoint for the API.""" 
    from utils.db import get_database

    db = get_database()
    db_status = "connected" if db._initialized else "disabled"

    return {
        "status": "healthy",
        "service": "Sentry Incident Analyzer",
        "version": "1.0.0",
        "database": db_status,
    }


@router.get("/api/listagents")
def list_agents_db():
    """Get agents list from stored procedure fn_ai_engine_list and return as a JSON list for ReactJS."""
    from utils.db import get_database
    db = get_database()
    
    if not db.is_enabled():
        raise HTTPException(status_code=400, detail="Database is disabled in configuration")
        
    if not db._initialized:
        raise HTTPException(status_code=500, detail="Database is not initialized or unreachable")

    conn = db.get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to acquire database connection")

    try:
        with conn.cursor() as cursor:
            cursor.callproc("fn_ai_engine_list")
            results = cursor.fetchall()
    except Exception as e:
        logger.error("Failed to execute stored procedure fn_ai_engine_list: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve agents via fn_ai_engine_list. Ensure procedure exists and parameters are correct: {e}"
        )
    finally:
        db.return_connection(conn)

    if results is None:
        raise HTTPException(
            status_code=500,
            detail="Failed to query agents from the database."
        )

    return results


@router.post("/api/addagent")
async def add_agent_db(request: AddAgentRequest):
    """Add a new agent by calling sp_ai_engine_insert procedure."""
    from utils.db import get_database
    db = get_database()
    
    if not db.is_enabled():
        raise HTTPException(status_code=400, detail="Database is disabled in configuration")
        
    if not db._initialized:
        raise HTTPException(status_code=500, detail="Database is not initialized or unreachable")

    name = request.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Agent name cannot be empty")

    conn = db.get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to acquire database connection")

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "CALL sp_ai_engine_insert(%s,%s,%s,%s,%s,%s);",
                (name, request.llm_model, request.conn_url, request.api_key, request.is_primary, request.is_active)
            )
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Failed to execute stored procedure sp_ai_engine_insert: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to add agent via sp_ai_engine_insert. Ensure procedure exists and parameters are correct: {e}"
        )
    finally:
        db.return_connection(conn)

    return {"status": "success", "message": f"Agent '{name}' added successfully"}


@router.post("/api/updateagent")
async def update_agent_db(request: UpdateAgentRequest):
    """Update an existing agent by calling sp_ai_engine_update procedure."""
    from utils.db import get_database
    db = get_database()
    
    if not db.is_enabled():
        raise HTTPException(status_code=400, detail="Database is disabled in configuration")
        
    if not db._initialized:
        raise HTTPException(status_code=500, detail="Database is not initialized or unreachable")

    name = request.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Agent name cannot be empty")

    conn = db.get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to acquire database connection")

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "CALL sp_ai_engine_update(%s::bigint,%s,%s,%s,%s,%s,%s);",
                (request.agent_id, name, request.llm_model, request.conn_url, request.api_key, request.is_primary, request.is_active)
            )
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Failed to execute stored procedure sp_ai_engine_update: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update agent via sp_ai_engine_update. Ensure procedure exists and parameters are correct: {e}"
        )
    finally:
        db.return_connection(conn)

    return {"status": "success", "message": f"Agent '{name}' updated successfully"}


@router.post("/api/deleteagent")
async def delete_agent(request: deleteAgentRequest):
    """Delete an existing agent by calling sp_ai_engine_delete procedure."""
    from utils.db import get_database
    db = get_database()
    
    if not db.is_enabled():
        raise HTTPException(status_code=400, detail="Database is disabled in configuration")
        
    if not db._initialized:
        raise HTTPException(status_code=500, detail="Database is not initialized or unreachable")

    name = request.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Agent name cannot be empty")

    conn = db.get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to acquire database connection")

    try:
        with conn.cursor() as cursor:
            cursor.execute("CALL sp_ai_engine_delete(%s::bigint);", (request.agent_id,))
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Failed to execute stored procedure sp_ai_engine_delete: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete agent via sp_ai_engine_delete. Ensure procedure exists and parameters are correct: {e}"
        )
    finally:
        db.return_connection(conn)

    return {"status": "success", "message": f"Agent '{name}' deleted successfully"} 


@router.post("/api/adduser")
async def add_user(request: InsertUser):
    """Add a new user by calling sp_ai_users_insert procedure."""
    from utils.db import get_database
    db = get_database()
    
    if not db.is_enabled():
        raise HTTPException(status_code=400, detail="Database is disabled in configuration")
        
    if not db._initialized:
        raise HTTPException(status_code=500, detail="Database is not initialized or unreachable")

    name = request.name.strip()
    username = request.username.strip()
    password = request.password.strip()
    role = request.role.strip()
    if not name or not username or not password or not role:
        raise HTTPException(status_code=400, detail="All fields must be non-empty")

    conn = db.get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to acquire database connection")

    try:
        with conn.cursor() as cursor:
            cursor.execute("CALL sp_ai_users_insert(%s,%s,%s,%s);", (name, username, password, role))
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Failed to execute stored procedure sp_ai_users_insert: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to add agent via sp_ai_engine_insert. Ensure procedure exists and parameters are correct: {e}"
        )
    finally:
        db.return_connection(conn)

    return {"status": "success", "message": f"Agent '{name}' added successfully"}   


@router.post("/api/login")
async def login(request: SecureValidateUser, req: Request):
    """Log in a user by calling fn_ai_users_validate_secure procedure."""
    from utils.db import get_database
    db = get_database()
    
    if not db.is_enabled():
        raise HTTPException(status_code=400, detail="Database is disabled in configuration")
        
    if not db._initialized:
        raise HTTPException(status_code=500, detail="Database is not initialized or unreachable")

    username = request.username.strip()
    password = request.password.strip()
    
    # Fallback to connection real IP and User-Agent if not provided in JSON body
    ipaddress = (request.ipaddress or "").strip()
    if not ipaddress:
        ipaddress = req.client.host if req.client else "127.0.0.1"
        
    useragent = (request.user_agent or "").strip()
    if not useragent:
        useragent = req.headers.get("user-agent", "Unknown")

    if not username or not password:
        raise HTTPException(status_code=400, detail="All fields must be non-empty")

    conn = db.get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to acquire database connection")

    try:
        with conn.cursor() as cursor:
            cursor.callproc("fn_authenticate_user", (username, password,ipaddress,useragent))
            result = cursor.fetchall()
            if not result:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid credentials"
                )
    except Exception as e:
        logger.error("Failed to execute stored procedure fn_authenticate_user_more: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to log in user : {e}"
        )
    finally:
        db.return_connection(conn)

    return {"status": "success", "message": f"User '{username}' logged in successfully"}    


@router.get("/api/getroles")
async def get_roles():
    """Get all roles from the database."""
    from utils.db import get_database
    db = get_database()
    
    if not db.is_enabled():
        raise HTTPException(status_code=400, detail="Database is disabled in configuration")
        
    if not db._initialized:
        raise HTTPException(status_code=500, detail="Database is not initialized or unreachable")

    conn = db.get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to acquire database connection")

    try:
        with conn.cursor() as cursor:
            cursor.callproc("sp_ai_roles_get")
            result = cursor.fetchall()
            if not result:
                raise HTTPException(
                    status_code=404,
                    detail="No roles found"
                )
    except Exception as e:
        logger.error("Failed to fetch roles: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get roles: {e}"
        )
    finally:
        db.return_connection(conn)

    return {"status": "success", "message": "Roles fetched successfully", "roles": result}


@router.post("/api/config/llm-model")
async def update_llm_model(request: LLMModelUpdateRequest) -> dict:
    """Update the configured LLM model in the .env file."""
    model = request.model.strip()
    if not model:
        raise HTTPException(status_code=400, detail="LLM model must be a non-empty string")

    try:
        update_env_variable("LLM_MODEL", model)
        return {
            "status": "success",
            "message": "LLM model updated successfully",
            "model": model,
        }
    except Exception as e:
        logger.error("Failed to update LLM_MODEL in .env: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to update LLM model: {e}")


@router.get("/api/llm-model")
async def get_llm_model_endpoint():
    """Return the active primary LLM model and temperature.

    Queries fn_ai_engine_get_primaryllm() in the database first;
    falls back to .env / os.environ if the database is unavailable.
    """
    try:
        cfg = get_llm_config()
    except Exception as e:
        logger.error("Failed to resolve LLM config: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="No Primary AI Agent is configured")

    if not cfg.get('model'):
        raise HTTPException(status_code=404, detail="No Primary AI Agent is configured")

    return {
        "status": "success",
        "message": "LLM config resolved successfully",
        "model": cfg['model'],
        "temperature": cfg['temperature'],
    }


@router.post("/api/analyze", response_model=None)
async def analyze_logs(
    request: AnalysisRequestWithModel,
    response_format: Optional[str] = "text",
#    username: str = Depends(get_current_username),
):
    """Analyze logs and generate incident remediations."""
    if not request.logs or not request.logs.strip():
        raise HTTPException(status_code=400, detail="Logs cannot be empty")

    logger.info(f"Processing analysis request: {len(request.logs)} characters")

    db = get_database()
    if not db.is_enabled():
        raise HTTPException(status_code=400, detail="Database is disabled in configuration")
    if not db._initialized:
        raise HTTPException(status_code=500, detail="Database is not initialized or unreachable")

    conn = db.get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to acquire database connection")

    analysis_id = None
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM fn_ai_engine_get_primaryllm()")
            row = cursor.fetchone()
            engine_id = row[0] if row else None
            requested_by = _resolve_requested_by(cursor, "admin")
            
            # Step 1: create the pending record BEFORE running analysis,
            # and commit it immediately — this is what lets a crash during
            # run_analysis() below still leave a visible 'pending' row
            # instead of vanishing entirely.
            cursor.execute(
                "SELECT * FROM fn_create_log_analysis(%s, %s, %s, %s, %s, %s, %s)",
                ("paste", request.logs, None, None, None, engine_id, requested_by),
            )
            analysis_id, analysis_code = cursor.fetchone()
            conn.commit()

        # Run analysis AFTER the pending record exists and is committed.
        try:
            result = normalize_analysis_result(run_analysis(request.logs))
            pretty_output = format_analysis(result)
        except Exception as e:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT fn_fail_log_analysis(%s, %s, %s)",
                    (analysis_id, str(e)[:4000], requested_by),
                )
                conn.commit()
            raise

        # Step 3: persist the report and mark completed — BEFORE the
        # response_format branch, so this happens regardless of which
        # format the caller asked for. The original code's early return
        # for "text" skipped persistence entirely; that's fixed here.
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT fn_complete_log_analysis(%s, %s::jsonb, %s::jsonb, %s)",
                (
                    analysis_id,
                    json.dumps(_build_entries_payload(result)),
                    json.dumps(_build_remediations_payload(result)),
                    requested_by,
                ),
            )
            conn.commit()

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        db.return_connection(conn)

    if response_format.lower() == "text":
        return PlainTextResponse(content=pretty_output)

    return AnalysisResponse(
        classified_entries=result.get("classified_entries", []),
        remediations=result.get("remediations", []),
        pretty_output=pretty_output,
        status="completed",
        message="Analysis completed successfully",
        analysis_code=analysis_code,
    )

@router.post("/api/analyze-file", response_model=None)
async def analyze_file(
    file: UploadFile = File(...),
    response_format: Optional[str] = "text",
#    username: str = Depends(get_current_username),
):
    """Analyze logs from an uploaded file.

    Supports .log, .txt, .json, and .csv file formats.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="File upload failed")

    logger.info(f"Processing file upload: {file.filename}")

    contents = await file.read()

    class UploadedBytesFile:
        def __init__(self, data: bytes, filename: str):
            self._data = data
            self.name = filename

        def read(self):
            return self._data

    raw_logs = read_uploaded_file(UploadedBytesFile(contents, file.filename))

    if not raw_logs.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty or invalid")

    if len(raw_logs) > _MAX_INPUT_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"Extracted text exceeds maximum size of {_MAX_INPUT_CHARS} characters",
        )

    checksum = hashlib.sha256(contents).hexdigest()

    db = get_database()
    if not db.is_enabled():
        raise HTTPException(status_code=400, detail="Database is disabled in configuration")
    if not db._initialized:
        raise HTTPException(status_code=500, detail="Database is not initialized or unreachable")

    conn = db.get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to acquire database connection")

    analysis_id = None
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM fn_ai_engine_get_primaryllm()")
            row = cursor.fetchone()
            engine_id = row[0]
            requested_by = _resolve_requested_by(cursor, "admin")  # stopgap — same caveat as before

            # Step 1: create the pending record, with real file provenance
            # this time — original_filename/file_size_bytes/checksum are
            # all populated because input_type is 'file_upload'. The DB's
            # ck_ai_log_analysis_file_fields CHECK constraint actively
            # requires these to be non-NULL when input_type='file_upload' —
            # passing None here (like the paste endpoint correctly does)
            # would fail the insert outright.
            cursor.execute(
                "SELECT * FROM fn_create_log_analysis(%s, %s, %s, %s, %s, %s, %s)",
                (
                    "file_upload",
                    raw_logs,
                    file.filename,
                    len(contents),
                    checksum,
                    engine_id,
                    requested_by,
                ),
            )
            analysis_id, analysis_code = cursor.fetchone()
            conn.commit()

        try:
            result = normalize_analysis_result(run_analysis(raw_logs))
            pretty_output = format_analysis(result)
        except Exception as e:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT fn_fail_log_analysis(%s, %s, %s)",
                    (analysis_id, str(e)[:4000], requested_by),
                )
                conn.commit()
            raise

        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT fn_complete_log_analysis(%s, %s::jsonb, %s::jsonb, %s)",
                (
                    analysis_id,
                    json.dumps(_build_entries_payload(result)),
                    json.dumps(_build_remediations_payload(result)),
                    requested_by,
                ),
            )
            conn.commit()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File analysis error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"File analysis failed: {str(e)}")
    finally:
        db.return_connection(conn)

    if response_format.lower() == "text":
        return PlainTextResponse(content=pretty_output)

    return AnalysisResponse(
        classified_entries=result.get("classified_entries", []),
        remediations=result.get("remediations", []),
        pretty_output=pretty_output,
        status="completed",
        message=f"Analysis completed successfully for {file.filename}",
        analysis_code=analysis_code,
    )

@router.get("/api/list-history")
async def get_short_history():
    """Return the active LLM model and temperature.

    Reads from .env first; falls back to fn_ai_engine_get_primaryllm() in the
    database if either value is absent, and persists the result to .env.
    """
    logger.info(f"Fetching list of analysis history")

    try:
        db = get_database()
        conn = db.get_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Failed to acquire database connection")
        
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM fn_list_log_analyses('completed',50,0)") 
            rows = cursor.fetchall()
            
    except Exception as e:
        logger.error("Failed to fetch analysis history: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch analysis history")

    
    return {
        "status": "success",
        "message": "Analysis history fetched successfully",
        "history": [{"id": row[0], "analysis_code": row[1], "status": row[2], "input_char_count": row[3], "engine_llm_model": row[4], "created_at": row[5], "completed_at": row[6], "status": "COMPLETED"} for row in rows]
    }

@router.get("/api/list-phistory")
async def get_history(
    p_id: Optional[str] = None,
    p_model_name: Optional[str] = None,
    p_status: Optional[str] = None,
    p_content_query: Optional[str] = None,
):
    """Return the active LLM model and temperature.

    Reads from .env first; falls back to fn_ai_engine_get_primaryllm() in the
    database if either value is absent, and persists the result to .env.
    """
    logger.info(f"Fetching list of analysis history")

    conn = None
    try:
        db = get_database()
        conn = db.get_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Failed to acquire database connection")
        
        # Convert empty strings to None
        p_id_val = p_id if p_id else None
        p_model_name_val = p_model_name if p_model_name else None
        p_status_val = p_status if p_status else None
        p_content_query_val = p_content_query if p_content_query else None

        with conn.cursor() as cursor:
            query = """
                SELECT * FROM fn_filter_log_analyses(
                    p_analysis_code => %s,
                    p_model_name => %s,
                    p_status => %s,
                    p_content_query => %s
                )
            """
            cursor.execute(query, (p_id_val, p_model_name_val, p_status_val, p_content_query_val))
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            
    except Exception as e:
        logger.error("Failed to fetch analysis history: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch analysis history")
    finally:
        if conn:
            db.return_connection(conn)

    history = []
    for row in rows:
        row_dict = dict(zip(columns, row))
        history.append({
            "id": row_dict.get("id"),
            "analysis_code": row_dict.get("analysis_code"),
            "status": row_dict.get("status"),
            "input_char_count": row_dict.get("input_char_count"),
            "engine_llm_model": row_dict.get("engine_llm_model"),
            "created_at": row_dict.get("created_at"),
            "completed_at": row_dict.get("completed_at"),
            "content_rank": row_dict.get("content_rank")
        })
    
    return {
        "status": "success",
        "message": "Analysis history fetched successfully",
        "history": history
    }

@router.get("/api/log-analysis")
async def get_analysis_detail(
    p_analysis_code: Optional[str] = None,
):
    """Return the active LLM model and temperature.

    Reads from .env first; falls back to fn_ai_engine_get_primaryllm() in the
    database if either value is absent, and persists the result to .env.
    """
    logger.info(f"Fetching list of analysis history")

    conn = None
    try:
        db = get_database()
        conn = db.get_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Failed to acquire database connection")
        
        # Convert empty strings to None
        p_analysis_code_val = p_analysis_code if p_analysis_code else None

        with conn.cursor() as cursor:
            query = """
                SELECT * FROM fn_get_log_analysis(
                    p_analysis_code => %s
                )
            """
            cursor.execute(query, (p_analysis_code_val,))
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            
    except Exception as e:
        logger.error("Failed to fetch analysis history: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch analysis history")
    finally:
        if conn:
            db.return_connection(conn)

    history = []
    for row in rows:
        row_dict = dict(zip(columns, row))
        history.append({
            "input_text": row_dict.get("input_text"),
            "error_message": row_dict.get("error_message"),
            "classified_entries": row_dict.get("classified_entries"),
            "remediations": row_dict.get("remediations")
        })
    
    return {
        "status": "success",
        "message": "Analysis history fetched successfully",
        "history": history
    }