from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_endpoint():
    payload = {
        "input_type": "email",
        "subject": "Urgent verify account",
        "body": "Please verify password immediately at http://bit.ly/login-now",
        "sender": "Security <alerts@paypa1.com>",
        "urls": ["http://bit.ly/login-now"],
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert "threat_score" in body
    assert body["risk_level"] in {"safe", "suspicious", "high_risk"}
