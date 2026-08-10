import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, UploadFile, File, HTTPException, Request
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

logger = logging.getLogger(__name__)

# FastAPI APIRouter initialization
router = APIRouter()


# ==================== Pydantic Models (Base Classes) ====================

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
    logs: str
    description: Optional[str] = None
    model_name: Optional[str] = "openai/gpt-4o"

    class Config:
        schema_extra = {
            "example": {
                "logs": "2026-05-10T10:23:45Z ERROR OOM killed process\n2026-05-10T10:24:12Z WARN High memory usage",
                "description": "Kubernetes cluster logs",
                "model_name": "openai/gpt-4o"
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
    """Return the active LLM model and temperature.

    Reads from .env first; falls back to fn_ai_engine_get_primaryllm() in the
    database if either value is absent, and persists the result to .env.
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
    request: AnalysisRequest,
    response_format: Optional[str] = "text",
):
    """Analyze logs and generate incident remediations.

    Args:
        request: AnalysisRequest containing raw logs
        response_format: "json" or "text"

    Returns:
        AnalysisResponse or plain text output depending on response_format

    Raises:
        HTTPException: If analysis fails or logs are empty
    """
    try:
        if not request.logs or not request.logs.strip():
            raise HTTPException(
                status_code=400,
                detail="Logs cannot be empty"
            )

        logger.info(f"Processing analysis request: {len(request.logs)} characters")

        # Run analysis
        result = normalize_analysis_result(run_analysis(request.logs))
        pretty_output = format_analysis(result)

        if response_format.lower() == "text":
            return PlainTextResponse(content=pretty_output)

        return AnalysisResponse(
            classified_entries=result.get("classified_entries", []),
            remediations=result.get("remediations", []),
            pretty_output=pretty_output,
            status="completed",
            message="Analysis completed successfully"
        )

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


@router.post("/api/analyze-file", response_model=None)
async def analyze_file(
    file: UploadFile = File(...),
    response_format: Optional[str] = "text",
):
    """Analyze logs from an uploaded file.

    Supports .log, .txt, .json, and .csv file formats.

    Args:
        file: Uploaded log file
        response_format: "json" or "text"

    Returns:
        AnalysisResponse with classified entries and remediations or plain text output

    Raises:
        HTTPException: If file upload or analysis fails
    """
    try:
        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail="File upload failed"
            )

        logger.info(f"Processing file upload: {file.filename}")

        # Read and parse uploaded file contents
        contents = await file.read()
        class UploadedBytesFile:
            def __init__(self, data: bytes, filename: str):
                self._data = data
                self.name = filename

            def read(self):
                return self._data

        raw_logs = read_uploaded_file(UploadedBytesFile(contents, file.filename))

        if not raw_logs.strip():
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty or invalid"
            )

        # Run analysis
        result = normalize_analysis_result(run_analysis(raw_logs))
        pretty_output = format_analysis(result)

        if response_format.lower() == "text":
            return PlainTextResponse(content=pretty_output)

        return AnalysisResponse(
            classified_entries=result.get("classified_entries", []),
            remediations=result.get("remediations", []),
            pretty_output=pretty_output,
            status="completed",
            message=f"Analysis completed successfully for {file.filename}"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File analysis error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"File analysis failed: {str(e)}"
        )
