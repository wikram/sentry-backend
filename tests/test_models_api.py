from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def _mock_response(json_data=None, status_code=200):
    request = httpx.Request("GET", "https://openrouter.ai/api/v1/models")
    return httpx.Response(status_code, json=json_data, request=request)


def test_get_models():
    models = [{"id": "openai/gpt-4o", "name": "GPT-4o"}]
    with patch("utils.llm_service.httpx.get", return_value=_mock_response({"data": models})) as mock_get:
        response = client.get("/api/models")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["models"] == models
    assert mock_get.call_args.args[0].endswith("/models")


def test_get_models_upstream_error():
    with patch("utils.llm_service.httpx.get", return_value=_mock_response({"error": "down"}, 503)):
        response = client.get("/api/models")

    assert response.status_code == 502


def test_get_models_unexpected_payload():
    with patch("utils.llm_service.httpx.get", return_value=_mock_response({"unexpected": []})):
        response = client.get("/api/models")

    assert response.status_code == 502


def test_get_models_connection_error():
    with patch("utils.llm_service.httpx.get", side_effect=httpx.ConnectError("refused")):
        response = client.get("/api/models")

    assert response.status_code == 502


def test_get_models_timeout():
    with patch("utils.llm_service.httpx.get", side_effect=httpx.ReadTimeout("slow")):
        response = client.get("/api/models")

    assert response.status_code == 504
