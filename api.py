from psycopg2.sql import NULL
import logging, json , hashlib
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Header, status, Depends
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

class LLMConfigRequest(BaseModel):
    """Request model for updating LLM model and/or temperature."""
    model: Optional[str] = None
    temperature: Optional[float] = None

    class Config:
        schema_extra = {
            "example": {
                "model": "openai/gpt-4o",
                "temperature": 0.2
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
    name: Optional[str] = None
    
    class Config:
        schema_extra = {
            "example": {
                "agent_id": 1,
                "name": "agent1"
            }
        }   


class AgentOperationRequest(BaseModel):
    """Unified request model for agent operations (add, update, delete)."""
    action: Optional[str] = None  # "add", "create", "update", "delete", "remove"
    agent_id: Optional[int] = None
    name: Optional[str] = None
    llm_model: Optional[str] = None
    temperature: Optional[float] = 0.2
    conn_url: Optional[str] = None
    api_key: Optional[str] = 'skprj-xxxxxxxx'
    is_primary: Optional[bool] = False
    is_active: Optional[bool] = True

    class Config:
        schema_extra = {
            "example": {
                "action": "add",
                "agent_id": 1,
                "name": "log_classifier_agent",
                "llm_model": "anthropic/claude-sonnet-4.5",
                "temperature": 0.2,
                "conn_url": "https://api.example.com",
                "api_key": "skprj-xxxxxxxx",
                "is_primary": False,
                "is_active": True
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
    analysis_code: Optional[str] = None

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


# ==================== Agent Database Operations ====================

def _execute_agent_insert(
    name: str,
    llm_model: str,
    conn_url: str,
    api_key: str = "",
    is_primary: bool = False,
    is_active: bool = True
) -> dict:
    """Helper to insert an AI agent into the database via sp_ai_engine_insert."""
    name = (name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Agent name cannot be empty")
    if not llm_model or not llm_model.strip():
        raise HTTPException(status_code=400, detail="LLM model cannot be empty")
    if not conn_url or not conn_url.strip():
        raise HTTPException(status_code=400, detail="Connection URL cannot be empty")

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
            cursor.execute(
                "CALL sp_ai_engine_insert(%s,%s,%s,%s,%s,%s);",
                (name, llm_model.strip(), conn_url.strip(), api_key or "", is_primary, is_active)
            )
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Failed to execute stored procedure sp_ai_engine_insert: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to add agent via sp_ai_engine_insert: {e}"
        )
    finally:
        db.return_connection(conn)

    return {"status": "success", "message": f"Agent '{name}' added successfully"}


def _execute_agent_update(
    agent_id: int,
    name: str,
    llm_model: str,
    conn_url: str,
    api_key: str = "",
    is_primary: bool = False,
    is_active: bool = True
) -> dict:
    """Helper to update an AI agent in the database via sp_ai_engine_update."""
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required for updating an agent")
    name = (name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Agent name cannot be empty")
    if not llm_model or not llm_model.strip():
        raise HTTPException(status_code=400, detail="LLM model cannot be empty")
    if not conn_url or not conn_url.strip():
        raise HTTPException(status_code=400, detail="Connection URL cannot be empty")

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
            cursor.execute(
                "CALL sp_ai_engine_update(%s::bigint,%s,%s,%s,%s,%s,%s);",
                (agent_id, name, llm_model.strip(), conn_url.strip(), api_key or "", is_primary, is_active)
            )
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Failed to execute stored procedure sp_ai_engine_update: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update agent via sp_ai_engine_update: {e}"
        )
    finally:
        db.return_connection(conn)

    return {"status": "success", "message": f"Agent '{name}' updated successfully"}


def _execute_agent_delete(agent_id: int, name: Optional[str] = None) -> dict:
    """Helper to delete an AI agent from the database via sp_ai_engine_delete."""
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required for deleting an agent")

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
            cursor.execute("CALL sp_ai_engine_delete(%s::bigint);", (agent_id,))
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Failed to execute stored procedure sp_ai_engine_delete: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete agent via sp_ai_engine_delete: {e}"
        )
    finally:
        db.return_connection(conn)

    display_name = f"'{name}'" if name else f"ID {agent_id}"
    return {"status": "success", "message": f"Agent {display_name} deleted successfully"}


def _execute_agent_list() -> list:
    """Helper to query the list of agents via fn_ai_engine_list."""
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
            detail=f"Failed to retrieve agents via fn_ai_engine_list: {e}"
        )
    finally:
        db.return_connection(conn)

    if results is None:
        raise HTTPException(
            status_code=500,
            detail="Failed to query agents from the database."
        )

    return results


# ==================== Unified /api/agents Endpoints ====================

@router.get("/api/agents")
def list_agents():
    """Retrieve all configured AI engines and agents."""
    return _execute_agent_list()


@router.post("/api/agents")
async def handle_agent_operation(request: AgentOperationRequest):
    """Unified endpoint for adding, updating, and deleting agents.

    Supported modes:
    1. Add / Create (default when agent_id is omitted or action='add'/'create'):
       Inserts a new agent via sp_ai_engine_insert.
    2. Update (when action='update' or agent_id is provided):
       Updates existing agent record via sp_ai_engine_update.
    3. Delete (when action='delete' or action='remove'):
       Deletes agent record via sp_ai_engine_delete.
    """
    action = (request.action or "").strip().lower()

    # 1. Delete operation
    if action in {"delete", "remove"}:
        if not request.agent_id:
            raise HTTPException(status_code=400, detail="agent_id is required for delete action")
        return _execute_agent_delete(request.agent_id, request.name)

    # 2. Update operation
    if action == "update" or (not action and request.agent_id is not None):
        if not request.agent_id:
            raise HTTPException(status_code=400, detail="agent_id is required for update action")
        if not request.name or not request.name.strip():
            raise HTTPException(status_code=400, detail="Agent name cannot be empty")
        if not request.llm_model or not request.llm_model.strip():
            raise HTTPException(status_code=400, detail="LLM model cannot be empty")
        if not request.conn_url or not request.conn_url.strip():
            raise HTTPException(status_code=400, detail="Connection URL cannot be empty")

        return _execute_agent_update(
            agent_id=request.agent_id,
            name=request.name.strip(),
            llm_model=request.llm_model.strip(),
            conn_url=request.conn_url.strip(),
            api_key=request.api_key or "",
            is_primary=bool(request.is_primary),
            is_active=bool(request.is_active),
        )

    # 3. Add / Create operation
    if action in {"add", "create", ""}:
        if not request.name or not request.name.strip():
            raise HTTPException(status_code=400, detail="Agent name cannot be empty")
        if not request.llm_model or not request.llm_model.strip():
            raise HTTPException(status_code=400, detail="LLM model cannot be empty")
        if not request.conn_url or not request.conn_url.strip():
            raise HTTPException(status_code=400, detail="Connection URL cannot be empty")

        return _execute_agent_insert(
            name=request.name.strip(),
            llm_model=request.llm_model.strip(),
            conn_url=request.conn_url.strip(),
            api_key=request.api_key or "",
            is_primary=bool(request.is_primary),
            is_active=bool(request.is_active),
        )

    raise HTTPException(
        status_code=400,
        detail=f"Unsupported action: '{request.action}'. Supported actions are 'add', 'update', or 'delete'",
    )


@router.put("/api/agents")
@router.put("/api/agents/{agent_id}")
async def update_agent_rest(request: UpdateAgentRequest, agent_id: Optional[int] = None):
    """RESTful endpoint to update an existing agent."""
    target_id = agent_id if agent_id is not None else request.agent_id
    if not target_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    return _execute_agent_update(
        agent_id=target_id,
        name=request.name.strip(),
        llm_model=request.llm_model.strip(),
        conn_url=request.conn_url.strip(),
        api_key=request.api_key or "",
        is_primary=bool(request.is_primary),
        is_active=bool(request.is_active),
    )


@router.delete("/api/agents/{agent_id}")
@router.delete("/api/agents")
async def delete_agent_rest(agent_id: Optional[int] = None, request: Optional[deleteAgentRequest] = None):
    """RESTful endpoint to delete an existing agent."""
    target_id = agent_id
    target_name = None
    if target_id is None and request is not None:
        target_id = request.agent_id
        target_name = request.name

    if not target_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    return _execute_agent_delete(target_id, target_name)


@router.post("/api/users")
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
            detail=f"Failed to add user via sp_ai_users_insert: {e}"
        )
    finally:
        db.return_connection(conn)

    return {"status": "success", "message": f"User '{name}' added successfully"}   


@router.post("/api/auth/login")
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


@router.get("/api/roles")
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

# ==================== Unified LLM Configuration Endpoints ====================

@router.get("/api/llm")
async def get_llm_config_endpoint():
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


@router.put("/api/llm")
@router.post("/api/llm")
async def update_llm_config_endpoint(request: LLMConfigRequest) -> dict:
    """Update configured LLM model and/or temperature in the .env file."""
    if not request.model and request.temperature is None:
        raise HTTPException(status_code=400, detail="At least one of model or temperature must be provided")

    try:
        updated_model = None
        updated_temp = None
        if request.model and request.model.strip():
            updated_model = request.model.strip()
            update_env_variable("LLM_MODEL", updated_model)
        if request.temperature is not None:
            updated_temp = float(request.temperature)
            update_env_variable("TEMPERATURE", str(updated_temp))

        return {
            "status": "success",
            "message": "LLM config updated successfully",
            "model": updated_model,
            "temperature": updated_temp,
        }
    except Exception as e:
        logger.error("Failed to update LLM config in .env: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to update LLM config: {e}")


# ==================== Unified Analysis Endpoints ====================

def _execute_analysis_pipeline(
    raw_logs: str,
    input_type: str = "paste",
    filename: Optional[str] = None,
    file_size_bytes: Optional[int] = None,
    checksum: Optional[str] = None,
    response_format: Optional[str] = "text",
    username: str = "admin",
):
    """Core log analysis workflow shared across JSON and file ingestion."""
    if not raw_logs or not raw_logs.strip():
        detail_msg = "Uploaded file is empty or invalid" if input_type == "file_upload" else "Logs cannot be empty"
        raise HTTPException(status_code=400, detail=detail_msg)

    if len(raw_logs) > _MAX_INPUT_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"Extracted text exceeds maximum size of {_MAX_INPUT_CHARS} characters",
        )

    logger.info("Processing analysis request: %d characters (type=%s)", len(raw_logs), input_type)

    from utils.db import get_database
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
            requested_by = _resolve_requested_by(cursor, username)

            # Create pending record before analysis begins
            cursor.execute(
                "SELECT * FROM fn_create_log_analysis(%s, %s, %s, %s, %s, %s, %s)",
                (
                    input_type,
                    raw_logs,
                    filename,
                    file_size_bytes,
                    checksum,
                    engine_id,
                    requested_by,
                ),
            )
            analysis_id, analysis_code = cursor.fetchone()
            conn.commit()

        # Run analysis workflow
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

        # Complete and persist analysis report
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
    except ValueError as e:
        logger.error("Validation error: %s", e)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Analysis error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        db.return_connection(conn)

    if response_format and response_format.lower() == "text":
        return PlainTextResponse(content=pretty_output)

    success_msg = f"Analysis completed successfully for {filename}" if filename else "Analysis completed successfully"
    return AnalysisResponse(
        classified_entries=result.get("classified_entries", []),
        remediations=result.get("remediations", []),
        pretty_output=pretty_output,
        status="completed",
        message=success_msg,
        analysis_code=analysis_code,
    )


_ANALYSIS_OPENAPI_EXTRA = {
    "requestBody": {
        "content": {
            "application/json": {
                "schema": getattr(AnalysisRequestWithModel, "model_json_schema", AnalysisRequestWithModel.schema)()
            },
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "file": {"type": "string", "format": "binary", "description": "Log file (.log, .txt, .json, .csv)"},
                        "logs": {"type": "string", "description": "Raw log text content"},
                    },
                }
            },
        }
    }
}


@router.post(
    "/api/analyze",
    response_model=None,
    openapi_extra=_ANALYSIS_OPENAPI_EXTRA,
)
async def analyze_logs(
    request: Request,
    response_format: Optional[str] = "text",
):
    """Analyze logs from either JSON payload or uploaded file (multipart/form-data)."""
    content_type = request.headers.get("content-type", "")

    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if uploaded_file and hasattr(uploaded_file, "read"):
            contents = await uploaded_file.read()
            filename = getattr(uploaded_file, "filename", "uploaded_file") or "uploaded_file"
            
            class UploadedBytesFile:
                def __init__(self, data: bytes, name: str):
                    self._data = data
                    self.name = name

                def read(self):
                    return self._data

            raw_logs = read_uploaded_file(UploadedBytesFile(contents, filename))
            checksum = hashlib.sha256(contents).hexdigest()
            return _execute_analysis_pipeline(
                raw_logs=raw_logs,
                input_type="file_upload",
                filename=filename,
                file_size_bytes=len(contents),
                checksum=checksum,
                response_format=response_format,
            )
        raw_logs_form = form.get("logs")
        if raw_logs_form:
            return _execute_analysis_pipeline(
                raw_logs=str(raw_logs_form),
                input_type="paste",
                response_format=response_format,
            )
        raise HTTPException(status_code=400, detail="No logs or file provided in multipart upload")

    # JSON payload
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON or missing body")

    req_data = AnalysisRequestWithModel(**body)
    return _execute_analysis_pipeline(
        raw_logs=req_data.logs,
        input_type="paste",
        response_format=response_format,
        username=req_data.user or "admin",
    )


# ==================== Unified History Endpoints ====================

@router.get("/api/history")
async def get_history(
    p_id: Optional[str] = None,
    analysis_code: Optional[str] = None,
    p_model_name: Optional[str] = None,
    model_name: Optional[str] = None,
    p_status: Optional[str] = None,
    status: Optional[str] = None,
    p_content_query: Optional[str] = None,
    content_query: Optional[str] = None,
    include_details: bool = False,
):
    """Unified endpoint for analysis history, filtering, and report details."""
    target_code = p_id or analysis_code
    target_model = p_model_name or model_name
    target_status = p_status or status
    target_content = p_content_query or content_query

    # Convert empty strings to None
    p_id_val = target_code if target_code else None
    p_model_name_val = target_model if target_model else None
    p_status_val = target_status if target_status else None
    p_content_query_val = target_content if target_content else None

    logger.info("Fetching analysis history (details=%s)", include_details)

    conn = None
    try:
        from utils.db import get_database
        db = get_database()
        conn = db.get_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Failed to acquire database connection")

        with conn.cursor() as cursor:
            if include_details and p_id_val:
                query = "SELECT * FROM fn_get_log_analysis(p_analysis_code => %s)"
                cursor.execute(query, (p_id_val,))
                columns = [desc[0] for desc in cursor.description]
                rows = cursor.fetchall()

                history = []
                for row in rows:
                    row_dict = dict(zip(columns, row))
                    history.append({
                        "analysis_code": p_id_val,
                        "input_text": row_dict.get("input_text"),
                        "error_message": row_dict.get("error_message"),
                        "classified_entries": row_dict.get("classified_entries"),
                        "remediations": row_dict.get("remediations"),
                    })
            else:
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
                        "content_rank": row_dict.get("content_rank"),
                    })

    except Exception as e:
        logger.error("Failed to fetch analysis history: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch analysis history")
    finally:
        if conn:
            db.return_connection(conn)

    return {
        "status": "success",
        "message": "Analysis history fetched successfully",
        "history": history,
    }


@router.get("/api/history/{analysis_code}")
async def get_history_by_code(analysis_code: str):
    """Retrieve full details for a specific analysis code."""
    return await get_history(p_id=analysis_code, include_details=True)

