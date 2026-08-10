import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv, set_key

from orchestrator.graph import build_graph
from orchestrator.state import IncidentState
from utils.log_parser import read_uploaded_file

logger = logging.getLogger(__name__)


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


def get_llm_config() -> dict:
    """Resolve LLM model and temperature using .env-first, DB-fallback priority.

    Resolution order:
      1. LLM_MODEL (or legacy LLM_MODE) environment variable / .env file.
      2. TEMPERATURE environment variable / .env file.
      3. If either value is missing, query fn_ai_engine_get_primaryllm() from DB
         and persist the results back into .env for future runs.

    Returns:
        dict with keys 'model' (str) and 'temperature' (float).
    """
    load_dotenv(override=False)  # ensure .env values are in os.environ

    env_model = (os.environ.get('LLM_MODEL') or '').strip()
    env_temp_raw = (os.environ.get('TEMPERATURE') or '').strip()
    env_temp: Optional[float] = None
    if env_temp_raw:
        try:
            env_temp = float(env_temp_raw)
        except ValueError:
            env_temp = None

    if env_model and env_temp is not None:
        # Both values present in .env — no DB call needed.
        return {'model': env_model, 'temperature': env_temp}

    # At least one value is missing — try the database.
    try:
        from utils.db import get_database
        db = get_database()
        if db.is_enabled() and db._initialized:
            conn = db.get_connection()
            if conn:
                try:
                    with conn.cursor() as cursor:
                        # Table-returning functions must be called with SELECT in psycopg2.
                        # callproc() is for stored procedures, not set-returning functions.
                        cursor.execute("SELECT llm_model, temperature FROM fn_ai_engine_get_primaryllm();")
                        row = cursor.fetchone()  # returns (llm_model, temperature) or None
                    if row:
                        db_model = (row[0] or '').strip()
                        db_temp = float(row[1]) if row[1] is not None else 0.2
                        # Use DB value only where .env was silent.
                        resolved_model = env_model or db_model
                        resolved_temp = env_temp if env_temp is not None else db_temp
                        # Set in-process environment only — never write to .env.
                        if resolved_model:
                            os.environ['LLM_MODEL'] = resolved_model
                        os.environ['TEMPERATURE'] = str(resolved_temp)
                        return {'model': resolved_model, 'temperature': resolved_temp}
                finally:
                    db.return_connection(conn)
    except Exception as exc:
        logger.warning("get_llm_config: DB fallback failed: %s", exc)

    # Final fallback — return whatever partial info we have.
    return {'model': env_model, 'temperature': env_temp if env_temp is not None else 0.2}


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
