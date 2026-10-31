from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_favicon():
    response = client.get("/favicon.ico")

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/x-icon"
    assert response.content[:4] == b"\x00\x00\x01\x00"  # ICO file signature


def test_favicon_hidden_from_openapi():
    assert "/favicon.ico" not in client.get("/openapi.json").json()["paths"]


def test_docs_pages_use_favicon():
    for path in ("/docs", "/redoc"):
        response = client.get(path)

        assert response.status_code == 200
        assert 'href="/favicon.ico"' in response.text
        assert "/openapi.json" in response.text
