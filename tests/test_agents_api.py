import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from main import app

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


def test_list_agents(mock_db):
    mock_instance, mock_cursor = mock_db
    mock_cursor.fetchall.return_value = [
        [1, "classifier_agent", "openai/gpt-4o", 0.2, "https://api.openai.com", True, True]
    ]

    response = client.get("/api/agents")
    assert response.status_code == 200
    assert response.json() == [
        [1, "classifier_agent", "openai/gpt-4o", 0.2, "https://api.openai.com", True, True]
    ]


def test_post_agents_add(mock_db):
    mock_instance, mock_cursor = mock_db

    payload = {
        "action": "add",
        "name": "remediation_agent",
        "llm_model": "anthropic/claude-sonnet-4.5",
        "temperature": 0.2,
        "conn_url": "https://api.anthropic.com",
        "api_key": "sk-test",
        "is_primary": False,
        "is_active": True
    }

    response = client.post("/api/agents", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "remediation_agent" in response.json()["message"]
    mock_cursor.execute.assert_called_once()
    assert "sp_ai_engine_insert" in mock_cursor.execute.call_args[0][0]


def test_post_agents_default_add(mock_db):
    """When action is omitted and agent_id is omitted, default to add/create."""
    mock_instance, mock_cursor = mock_db

    payload = {
        "name": "default_add_agent",
        "llm_model": "openai/gpt-4o",
        "conn_url": "https://api.openai.com",
        "api_key": "sk-test"
    }

    response = client.post("/api/agents", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "default_add_agent" in response.json()["message"]
    assert "sp_ai_engine_insert" in mock_cursor.execute.call_args[0][0]


def test_post_agents_update_action(mock_db):
    mock_instance, mock_cursor = mock_db

    payload = {
        "action": "update",
        "agent_id": 42,
        "name": "updated_agent",
        "llm_model": "openai/gpt-4o-mini",
        "conn_url": "https://api.openai.com",
        "api_key": "sk-test",
        "is_primary": True,
        "is_active": True
    }

    response = client.post("/api/agents", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "updated successfully" in response.json()["message"]
    assert "sp_ai_engine_update" in mock_cursor.execute.call_args[0][0]


def test_post_agents_delete_action(mock_db):
    mock_instance, mock_cursor = mock_db

    payload = {
        "action": "delete",
        "agent_id": 42,
        "name": "agent_to_delete"
    }

    response = client.post("/api/agents", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "deleted successfully" in response.json()["message"]
    assert "sp_ai_engine_delete" in mock_cursor.execute.call_args[0][0]


def test_put_agents_rest(mock_db):
    mock_instance, mock_cursor = mock_db

    payload = {
        "agent_id": 10,
        "name": "put_agent",
        "llm_model": "openai/gpt-4o",
        "conn_url": "https://api.openai.com",
        "api_key": "sk-test",
        "is_primary": False,
        "is_active": True
    }

    response = client.put("/api/agents/10", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "sp_ai_engine_update" in mock_cursor.execute.call_args[0][0]


def test_delete_agents_rest(mock_db):
    mock_instance, mock_cursor = mock_db

    response = client.delete("/api/agents/10")
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "sp_ai_engine_delete" in mock_cursor.execute.call_args[0][0]


def test_validation_errors(mock_db):
    # Empty name
    resp = client.post("/api/agents", json={"action": "add", "name": "", "llm_model": "gpt-4o", "conn_url": "http://x"})
    assert resp.status_code == 400
    assert "name cannot be empty" in resp.json()["detail"]

    # Delete without agent_id
    resp = client.post("/api/agents", json={"action": "delete"})
    assert resp.status_code == 400
    assert "agent_id is required" in resp.json()["detail"]

    # Unsupported action
    resp = client.post("/api/agents", json={"action": "invalid_action", "name": "test"})
    assert resp.status_code == 400
    assert "Unsupported action" in resp.json()["detail"]
