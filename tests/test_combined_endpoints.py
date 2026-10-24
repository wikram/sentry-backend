import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from main import app
from utils.helpers import run_analysis
from agents.jira_ticket import _create_jira_tickets_batch

client = TestClient(app)


@pytest.fixture
def mock_db():
    with patch("utils.db.get_database") as mock_get_db:
        mock_instance = MagicMock()
        mock_instance.is_enabled.return_value = True
        mock_instance._initialized = True

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_instance.get_connection.return_value = mock_conn

        mock_get_db.return_value = mock_instance
        yield mock_instance, mock_cursor


def test_get_history_unified(mock_db):
    mock_instance, mock_cursor = mock_db
    mock_cursor.description = [
        ("id",), ("analysis_code",), ("status",), ("input_char_count",),
        ("engine_llm_model",), ("created_at",), ("completed_at",), ("content_rank",)
    ]
    mock_cursor.fetchall.return_value = [
        [1, "ANL-101", "completed", 500, "openai/gpt-4o", "2026-01-01", "2026-01-01", 1]
    ]

    response = client.get("/api/history?p_status=completed")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert len(data["history"]) == 1
    assert data["history"][0]["analysis_code"] == "ANL-101"


def test_get_history_with_details(mock_db):
    mock_instance, mock_cursor = mock_db
    mock_cursor.description = [
        ("input_text",), ("error_message",), ("classified_entries",), ("remediations",)
    ]
    mock_cursor.fetchall.return_value = [
        ["raw logs text", None, [{"severity": "CRITICAL"}], [{"issue_summary": "OOM"}]]
    ]

    response = client.get("/api/history?p_id=ANL-101&include_details=true")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert len(data["history"]) == 1
    assert data["history"][0]["analysis_code"] == "ANL-101"
    assert data["history"][0]["input_text"] == "raw logs text"


def test_get_and_put_llm_config(mock_db):
    with patch("api.get_llm_config") as mock_get_cfg, \
         patch("api.update_env_variable") as mock_update_env:
        mock_get_cfg.return_value = {"model": "openai/gpt-4o", "temperature": 0.2}

        # GET /api/config/llm
        resp = client.get("/api/config/llm")
        assert resp.status_code == 200
        assert resp.json()["model"] == "openai/gpt-4o"
        assert resp.json()["temperature"] == 0.2

        # PUT /api/config/llm
        put_resp = client.put("/api/config/llm", json={"model": "anthropic/claude-sonnet-4.5", "temperature": 0.1})
        assert put_resp.status_code == 200
        assert put_resp.json()["model"] == "anthropic/claude-sonnet-4.5"
        assert put_resp.json()["temperature"] == 0.1
        assert mock_update_env.call_count == 2


def test_jira_batch_creation():
    mock_jira = MagicMock()
    mock_issue1 = MagicMock(key="OPS-101")
    mock_issue2 = MagicMock(key="OPS-102")
    mock_jira.create_issues.return_value = [
        {"issue": mock_issue1, "error": None},
        {"issue": mock_issue2, "error": None}
    ]

    ticket_specs = [
        {"title": "OOM crash", "priority": "Critical", "description": "Crash details"},
        {"title": "DB timeout", "priority": "High", "description": "Timeout details"}
    ]

    with patch.dict("os.environ", {"JIRA_PROJECT_KEY": "OPS", "JIRA_INSTANCE_URL": "https://jira.example.com"}):
        results = _create_jira_tickets_batch(mock_jira, ticket_specs)
        assert len(results) == 2
        assert results[0]["key"] == "OPS-101"
        assert results[0]["status"] == "created"
        assert results[1]["key"] == "OPS-102"
        mock_jira.create_issues.assert_called_once()


def test_get_history_by_code_path(mock_db):
    mock_instance, mock_cursor = mock_db
    mock_cursor.description = [
        ("input_text",), ("error_message",), ("classified_entries",), ("remediations",)
    ]
    mock_cursor.fetchall.return_value = [
        ["sample crash logs", None, [], []]
    ]

    response = client.get("/api/history/ANL-202")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["history"][0]["analysis_code"] == "ANL-202"
    assert data["history"][0]["input_text"] == "sample crash logs"


def test_removed_legacy_endpoints_return_404(mock_db):
    """Verify that all removed legacy endpoints return 404 Not Found."""
    removed_get_endpoints = [
        "/api/listagents",
        "/api/llm-model",
        "/api/list-phistory",
        "/api/list-history",
        "/api/log-analysis",
        "/api/getroles",
    ]
    for endpoint in removed_get_endpoints:
        response = client.get(endpoint)
        assert response.status_code == 404, f"Expected 404 for GET {endpoint}, got {response.status_code}"

    removed_post_endpoints = [
        "/api/addagent",
        "/api/updateagent",
        "/api/deleteagent",
        "/api/config/llm-model",
        "/api/analyze-file",
        "/api/adduser",
        "/api/login",
    ]
    for endpoint in removed_post_endpoints:
        response = client.post(endpoint, json={})
        assert response.status_code == 404, f"Expected 404 for POST {endpoint}, got {response.status_code}"


def test_users_and_roles(mock_db):
    mock_instance, mock_cursor = mock_db

    # POST /api/users
    resp_user = client.post("/api/users", json={
        "name": "Alice Developer",
        "username": "alice",
        "password": "secretpassword",
        "role": "admin"
    })
    assert resp_user.status_code == 200
    assert resp_user.json()["status"] == "success"
    assert "Alice Developer" in resp_user.json()["message"]
    assert "sp_ai_users_insert" in mock_cursor.execute.call_args[0][0]

    # GET /api/roles
    mock_cursor.fetchall.return_value = [["admin", "Administrator"], ["viewer", "Read-only"]]
    resp_roles = client.get("/api/roles")
    assert resp_roles.status_code == 200
    assert resp_roles.json()["status"] == "success"
    assert len(resp_roles.json()["roles"]) == 2

    # POST /api/auth/login
    mock_cursor.fetchall.return_value = [["usr-1", "alice"]]
    resp_login = client.post("/api/auth/login", json={
        "username": "alice",
        "password": "secretpassword"
    })
    assert resp_login.status_code == 200
    assert resp_login.json()["status"] == "success"
    assert "alice" in resp_login.json()["message"]


def test_analyze_unified_json(mock_db):
    mock_instance, mock_cursor = mock_db
    # First query for engine_id: fetchone returns [1]
    # Second query for requested_by: fetchone returns ["admin-uuid"]
    # Third query for fn_create_log_analysis: fetchone returns [10, "ANL-555"]
    mock_cursor.fetchone.side_effect = [
        [1],
        ["admin-uuid"],
        [10, "ANL-555"],
    ]

    mock_analysis_result = {
        "classified_entries": [{
            "timestamp": "2026-05-10T10:23:45Z",
            "severity": "CRITICAL",
            "category": "OOM",
            "source": "k8s",
            "raw_line": "OOM killed process",
            "summary": "Process was killed by OOM",
        }],
        "remediations": [{
            "issue_summary": "OOM Crash",
            "root_cause": "Memory exceeded limit",
            "fix_steps": ["Increase memory limits"],
            "rationale": "Container limits were too low",
            "confidence": 0.95,
            "linked_log_entries": [0],
        }]
    }

    with patch("api.run_analysis", return_value=mock_analysis_result), \
         patch("api.format_analysis", return_value="Formatted Analysis Report"):
        
        # Test JSON response
        resp_json = client.post(
            "/api/analyze?response_format=json",
            json={"logs": "2026-05-10T10:23:45Z ERROR OOM killed process"}
        )
        assert resp_json.status_code == 200
        data = resp_json.json()
        assert data["status"] == "completed"
        assert data["analysis_code"] == "ANL-555"
        assert len(data["classified_entries"]) == 1
        assert len(data["remediations"]) == 1


def test_analyze_unified_file_upload(mock_db):
    mock_instance, mock_cursor = mock_db
    mock_cursor.fetchone.side_effect = [
        [1],
        ["admin-uuid"],
        [11, "ANL-777"],
    ]

    mock_analysis_result = {
        "classified_entries": [],
        "remediations": []
    }

    fake_file_content = b"2026-05-10T10:00:00Z ERROR Fatal database connection lost\n"

    with patch("api.run_analysis", return_value=mock_analysis_result), \
         patch("api.format_analysis", return_value="Formatted Output"):
        
        # Send multipart file upload to /api/analyze
        resp = client.post(
            "/api/analyze?response_format=json",
            files={"file": ("sys_errors.log", fake_file_content, "text/plain")}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["analysis_code"] == "ANL-777"
        assert "sys_errors.log" in data["message"]

