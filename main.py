#!/usr/bin/env python3
"""Main entry point for the Sentry DevOps Incident Analyzer.

Provides both CLI and REST API interfaces for the incident analysis workflow:
1. Loads raw logs from a file or API request
2. Classifies log entries by severity and category
3. Generates remediation steps
4. Routes to downstream agents (cookbook, Slack, JIRA) based on severity
5. Outputs analysis results

USAGE:

  REST API Server (Uvicorn):
    uvicorn main:app --reload
    uvicorn main:app --host 0.0.0.0 --port 8000
    
  REST API Server (Direct):
    python main.py --server
    python main.py --server --host 0.0.0.0 --port 8000

  CLI Analysis:
    python main.py sample_logs/app_errors.csv
    python main.py sample_logs/k8s_crash.json --json
    python main.py logs/production.log --output results.json

API Endpoints:
  GET  /api/health           - Health check
  POST /api/analyze          - Analyze logs (JSON)
  POST /api/analyze-file     - Analyze uploaded log files
  GET  /docs                 - Interactive API documentation (Swagger UI)
  GET  /redoc                - Alternative API documentation (ReDoc)
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv, set_key
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, HTMLResponse
from pydantic import BaseModel
import uvicorn

from logger import configure_logging

from orchestrator.graph import build_graph, get_agent_definitions
from orchestrator.state import IncidentState
from utils.db import init_database, close_database
from utils.log_parser import read_uploaded_file


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# FastAPI app initialization
app = FastAPI(
    title="Sentry Incident Analyzer API",
    description="AI-powered incident analysis and remediation workflow",
    version="1.0.0",
)

# CORS middleware for React UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this based on your React UI domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic models for API requests/responses
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

    class Config:
        schema_extra = {
            "example": {
                "username": "admin",
                "password": "password"
            }
        }

class InsertUser(BaseModel):
    """Request model for inserting user."""
    name: str
    username: str
    password: str
    role: str
    
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
    conn_url: str
    api_key: str='skprj-xxxxxxxx'
    is_primary: bool = False
    is_active: bool = True

    class Config:
        schema_extra = {
            "example": {
                "name": "log_classifier_agent",
                "llm_model": "anthropic/claude-sonnet-4.5",
                "conn_url": "https://api.example.com",
                "api_key": "",
                "is_primary":  False,
                "is_active": True
            }
        }

class UpdateAgentRequest(BaseModel):
    """Request model for updating an existing agent."""
    agent_id: int
    name: str
    llm_model: str
    conn_url: str
    api_key: str='skprj-xxxxxxxx'
    is_primary: bool = False
    is_active: bool = False

    class Config:
        schema_extra = {
            "example": {
                "agent_id": 1,  # Agent ID is required for updating an existing agent.
                "name": "log_classifier_agent",
                "llm_model": "anthropic/claude-sonnet-4.5",
                "conn_url": "https://api.example.com",
                "api_key": "",
                "is_primary":  False,
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



def load_logs(file_path: str) -> str:
    """Load log contents from a file.

    Args:
        file_path: Path to the log file (.log, .txt, .json, or .csv)

    Returns:
        Raw log contents as a string

    Raises:
        FileNotFoundError: If the file does not exist
        IOError: If the file cannot be read
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    logger.info(f"Loading logs from: {file_path}")

    with open(path, "rb") as f:
        class FileWrapper:
            def __init__(self, file_obj, file_name):
                self.file_obj = file_obj
                self.name = file_name

            def read(self):
                return self.file_obj.read()

        wrapped_file = FileWrapper(f, path.name)
        raw_logs = read_uploaded_file(wrapped_file)

    if not raw_logs.strip():
        raise ValueError(f"Log file is empty: {file_path}")

    logger.info(f"Loaded {len(raw_logs)} characters from log file")
    return raw_logs


def run_analysis(raw_logs: str) -> dict:
    """Run the incident analysis workflow on raw logs.

    Args:
        raw_logs: Raw log contents as a string

    Returns:
        Analysis results containing classified entries, remediations, and notifications
    """
    logger.info("Building analysis graph...")
    graph = build_graph()

    # Initialize incident state with LLM configuration
    initial_state: IncidentState = {
        "raw_logs": raw_logs,
        "classified_entries": [],
        "remediations": [],
        "llm": {},  # LLM configuration for agents (can be extended with temperature, model, etc.)
    }

    logger.info("Starting incident analysis workflow...")
    try:
        # Run the graph
        result = graph.invoke(initial_state)
        logger.info("Incident analysis workflow completed successfully")
        return result
    except Exception as e:
        logger.error(f"Error during analysis workflow: {e}", exc_info=True)
        raise


def normalize_analysis_result(result: dict) -> dict:
    """Normalize analysis output to satisfy API response models."""
    normalized = result.copy()

    classified_entries = normalized.get("classified_entries", [])
    normalized_entries = []
    for entry in classified_entries:
        timestamp = str(entry.get("timestamp", "")) if entry.get("timestamp") is not None else ""
        if not timestamp.strip():
            timestamp = datetime.now(timezone.utc).isoformat()

        normalized_entries.append({
            "timestamp": timestamp,
            "severity": str(entry.get("severity", "UNKNOWN")),
            "category": str(entry.get("category", "unknown")),
            "source": str(entry.get("source", "unknown")),
            "raw_line": str(entry.get("raw_line", "")),
            "summary": str(entry.get("summary", "")),
        })
    normalized["classified_entries"] = normalized_entries

    remediations = normalized.get("remediations", [])
    normalized_remediations = []
    for remediation in remediations:
        normalized_remediations.append({
            "issue_summary": str(remediation.get("issue_summary", "")),
            "root_cause": str(remediation.get("root_cause", "")),
            "fix_steps": [str(step) for step in remediation.get("fix_steps", [])],
            "rationale": str(remediation.get("rationale", "")),
            "confidence": float(remediation.get("confidence", 0.0)) if remediation.get("confidence") is not None else 0.0,
            "linked_log_entries": [int(idx) for idx in remediation.get("linked_log_entries", []) if isinstance(idx, int)],
        })
    normalized["remediations"] = normalized_remediations

    return normalized


def update_env_variable(key: str, value: str, env_file: Path = Path('.env')) -> None:
    """Update or add a key/value pair in the .env file."""
    if not env_file.exists():
        env_file.write_text("")

    load_dotenv(env_file, override=True)
    set_key(str(env_file), key, value)
    os.environ[key] = value


# ==================== FastAPI Endpoints ====================


@app.on_event("startup")
async def startup_event():
    """Log startup event when app starts."""
    # Configure logging from config.yaml
    configure_logging()

    # Initialize database if enabled
    db_connected = init_database()

    logger.info("=" * 80)
    logger.info("Sentry Incident Analyzer API Server Started")
    logger.info("=" * 80)
    logger.info("📚 Interactive API docs available at: http://localhost:8000/docs")
    logger.info("📘 Alternative docs available at: http://localhost:8000/redoc")
    logger.info("❤️  Health check: http://localhost:8000/api/health")
    if db_connected:
        from utils.db import get_database
        db = get_database()
        host = db.config.get("host", "localhost")
        port = db.config.get("port", 5432)
        db_name = db.config.get("name", "sentry")
        logger.info(f"🟢 Database Status: Connected successfully ({db_name} @ {host}:{port})")
    logger.info("=" * 80)


@app.on_event("shutdown")
async def shutdown_event():
    """Log shutdown event when app stops."""
    # Close database connections
    close_database()

    logger.info("=" * 80)
    logger.info("Sentry Incident Analyzer API Server Stopped")
    logger.info("=" * 80)


@app.get("/")
def root():
    """Root endpoint with API information."""
    return {
        "service": "Sentry Incident Analyzer",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/api/health"
    }


@app.get("/api/health")
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

@app.get("/api/listagents")
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
            # Call procedure using CALL statement with 2 parameters
            #cursor.execute("SELECT id,name,llm_model,conn_url,is_primary FROM fn_ai_engine_list();")
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

    # Query the table directly so we can include llm_model, which fn_ai_engine_list()
    # does not expose in its RETURNS TABLE definition.
    #results = db.execute_query(
    #    "SELECT id, name, llm_model, is_primary FROM ai_engine ORDER BY id;"
    #)

    if results is None:
        raise HTTPException(
            status_code=500,
            detail="Failed to query agents from the database."
        )

    return results


@app.post("/api/addagent")
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
            # Call procedure using CALL statement with 2 parameters
            cursor.execute("CALL sp_ai_engine_insert(%s,%s,%s,%s,%s,%s);", (name, request.llm_model,request.conn_url,request.api_key,request.is_primary,request.is_active))
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

@app.post("/api/updateagent")
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
            # Call procedure using CALL statement with 2 parameters 
            cursor.execute("CALL sp_ai_engine_update(%s::bigint,%s,%s,%s,%s,%s,%s);", (request.agent_id,name, request.llm_model,request.conn_url,request.api_key,request.is_primary,request.is_active))
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

@app.post("/api/deleteagent")
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
            # Call procedure using CALL statement with 2 parameters 
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

@app.post("/api/adduser")
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
            # Call procedure using CALL statement with 2 parameters
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

@app.post("/api/login")
async def login(request: SecureValidateUser):
    """Log in a user by calling fn_ai_users_validate_secure procedure."""
    from utils.db import get_database
    db = get_database()
    
    if not db.is_enabled():
        raise HTTPException(status_code=400, detail="Database is disabled in configuration")
        
    if not db._initialized:
        raise HTTPException(status_code=500, detail="Database is not initialized or unreachable")

    username = request.username.strip()
    password = request.password.strip()
    if not username or not password:
        raise HTTPException(status_code=400, detail="All fields must be non-empty")

    conn = db.get_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to acquire database connection")

    try:
        with conn.cursor() as cursor:
            # Call procedure using CALL statement with 2 parameters
            cursor.callproc("fn_ai_users_validate_secure", (username, password))
            result = cursor.fetchall()
            if not result:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid credentials"
                )
    except Exception as e:
        logger.error("Failed to execute stored procedure fn_ai_users_validate_secure: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to log in user : {e}"
        )
    finally:
        db.return_connection(conn)

    return {"status": "success", "message": f"User '{username}' logged in successfully"}    

@app.get("/api/getroles")
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
            # Call procedure using CALL statement with 2 parameters
            cursor.execute("CALL sp_ai_roles_get();")
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("Failed to execute stored procedure sp_ai_roles_get: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get roles via sp_ai_roles_get. Ensure procedure exists and parameters are correct: {e}"
        )
    finally:
        db.return_connection(conn)

    return {"status": "success", "message": f"User '{username}' logged in successfully"}    

@app.post("/api/config/llm-model")
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


@app.post("/api/analyze", response_model=None)
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


@app.post("/api/analyze-file", response_model=None)
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

def format_analysis(result: dict) -> str:
    """Produce a human-readable representation of the analysis results."""
    lines = ["INCIDENT ANALYSIS RESULTS", "=" * 80]

    classified_entries = result.get("classified_entries", [])
    if classified_entries:
        lines.append(f"\n📋 CLASSIFIED LOG ENTRIES ({len(classified_entries)})")
        lines.append("-" * 80)
        for i, entry in enumerate(classified_entries, 1):
            lines.append(f"\n{i}. [{entry['severity']}] {entry['category']} - {entry['source']}")
            lines.append(f"   Time: {entry['timestamp']}")
            lines.append(f"   Summary: {entry['summary']}")
            lines.append(f"   Raw: {entry['raw_line'][:100]}...")

    remediations = result.get("remediations", [])
    if remediations:
        lines.append(f"\n🔧 REMEDIATION STEPS ({len(remediations)})")
        lines.append("-" * 80)
        for i, remediation in enumerate(remediations, 1):
            lines.append(f"\n{i}. {remediation['issue_summary']}")
            lines.append(f"   Root Cause: {remediation['root_cause']}")
            lines.append(f"   Confidence: {remediation['confidence']:.1%}")
            lines.append(f"   Fix Steps:")
            for j, step in enumerate(remediation["fix_steps"], 1):
                lines.append(f"     {j}. {step}")
            lines.append(f"   Rationale: {remediation['rationale']}")

    lines.append("\n" + "=" * 80 + "\n")
    return "\n".join(lines)


def display_results(result: dict) -> None:
    """Display the analysis results in a formatted way.

    Args:
        result: Analysis results from the workflow
    """
    print(format_analysis(result))


def main():
    """Main entry point for the incident analyzer."""
    # Configure logging from config.yaml
    configure_logging()

    parser = argparse.ArgumentParser(
        description="Sentry DevOps Incident Analyzer - CLI and REST API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
QUICK START:

  1. Start REST API Server (Recommended):
     uvicorn main:app --reload
     
  2. Or start with Python:
     python main.py --server
     
  3. Run CLI analysis:
     python main.py sample_logs/app_errors.csv
     python main.py sample_logs/k8s_crash.json --json
     python main.py logs/production.log --output results.json

API Documentation:
  After starting the server, visit: http://localhost:8000/docs
        """,
    )

    parser.add_argument(
        "log_file",
        nargs="?",
        help="Path to the log file to analyze (.log, .txt, .json, or .csv)",
    )
    parser.add_argument(
        "--server",
        action="store_true",
        help="Run as FastAPI server (alternative to using: uvicorn main:app)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Server host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Server port (default: 8000)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of formatted text (CLI only)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Save results to a JSON file (CLI only)",
        metavar="FILE",
    )

    args = parser.parse_args()

    # Server mode
    if args.server:
        logger.info(f"Starting Sentry Incident Analyzer API server on {args.host}:{args.port}")
        print(f"\n🚀 API Server starting at http://{args.host}:{args.port}")
        print(f"📚 API Documentation at http://{args.host}:{args.port}/docs")
        print(f"   Press Ctrl+C to stop\n")
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="info"
        )
        return 0

    # CLI mode
    if not args.log_file:
        parser.print_help()
        print("\n" + "=" * 80)
        print("To run the REST API server, use one of:")
        print("  1. uvicorn main:app --reload")
        print("  2. python main.py --server")
        print("=" * 80)
        return 1

    try:
        # Load logs
        raw_logs = load_logs(args.log_file)

        # Run analysis
        result = run_analysis(raw_logs)

        # Display or save results
        if args.json:
            output = json.dumps(result, indent=2, default=str)
            print(output)
        else:
            display_results(result)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(result, f, indent=2, default=str)
            logger.info(f"Results saved to {output_path}")

        return 0

    except FileNotFoundError as e:
        logger.error(f"File error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
