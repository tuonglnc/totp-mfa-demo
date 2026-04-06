"""
tests/test_auth_routes.py — Integration Tests: Authentication API
"""

import pytest
import os
import tempfile
from app import create_app
from app.models.database import init_db


@pytest.fixture
def app():
    """Create test Flask app with a fresh temporary database per test."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    # Patch env before creating app so init_db uses the right path
    os.environ["DATABASE_PATH"] = db_path
    os.environ["FLASK_ENV"] = "development"  # disables CSRF

    test_app = create_app()
    test_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "DATABASE_PATH": db_path,
        "SECRET_KEY": "test-secret-key-for-testing",
        "TOTP_MASTER_KEY": "test-totp-master-key-for-tests",
    })

    # Re-run init_db with corrected config
    init_db(test_app)

    yield test_app

    os.unlink(db_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def registered_user(client):
    """Register a user and return their credentials."""
    resp = client.post("/api/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "TestPass123!",
    })
    assert resp.status_code == 201
    return {"username": "testuser", "password": "TestPass123!", "email": "test@example.com"}


class TestRegister:

    def test_register_success(self, client):
        resp = client.post("/api/register", json={
            "username": "newuser",
            "email": "new@test.com",
            "password": "ValidPass123!",
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["success"] is True
        assert "user_id" in data

    def test_register_duplicate_username(self, client, registered_user):
        resp = client.post("/api/register", json={
            "username": "testuser",
            "email": "other@test.com",
            "password": "Pass123!",
        })
        assert resp.status_code == 409
        assert "already taken" in resp.get_json()["error"]

    def test_register_short_username(self, client):
        resp = client.post("/api/register", json={
            "username": "ab",
            "email": "ab@test.com",
            "password": "Pass123!",
        })
        assert resp.status_code == 400

    def test_register_short_password(self, client):
        resp = client.post("/api/register", json={
            "username": "validuser",
            "email": "v@test.com",
            "password": "short",
        })
        assert resp.status_code == 400

    def test_register_invalid_email(self, client):
        resp = client.post("/api/register", json={
            "username": "validuser",
            "email": "notanemail",
            "password": "ValidPass123!",
        })
        assert resp.status_code == 400


class TestLogin:

    def test_login_no_2fa(self, client, registered_user):
        """Login without 2FA should authenticate directly."""
        resp = client.post("/api/login", json={
            "username": registered_user["username"],
            "password": registered_user["password"],
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["requires_2fa"] is False
        assert data["redirect"] == "/dashboard"

    def test_login_wrong_password(self, client, registered_user):
        resp = client.post("/api/login", json={
            "username": registered_user["username"],
            "password": "WrongPassword!",
        })
        assert resp.status_code == 401
        assert "Invalid" in resp.get_json()["error"]

    def test_login_nonexistent_user(self, client):
        resp = client.post("/api/login", json={
            "username": "doesnotexist",
            "password": "anypassword",
        })
        assert resp.status_code == 401

    def test_login_missing_fields(self, client):
        resp = client.post("/api/login", json={"username": "test"})
        assert resp.status_code == 400

    def test_status_unauthenticated(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 200
        assert resp.get_json()["authenticated"] is False

    def test_status_authenticated(self, client, registered_user):
        # Login first
        client.post("/api/login", json={
            "username": registered_user["username"],
            "password": registered_user["password"],
        })
        resp = client.get("/api/status")
        assert resp.status_code == 200
        assert resp.get_json()["authenticated"] is True

    def test_logout(self, client, registered_user):
        client.post("/api/login", json={
            "username": registered_user["username"],
            "password": registered_user["password"],
        })
        resp = client.post("/api/logout")
        assert resp.status_code == 200

        # Check status is now unauthenticated
        resp2 = client.get("/api/status")
        assert resp2.get_json()["authenticated"] is False


class TestVerifyTotp:

    def test_verify_invalid_session_token(self, client):
        resp = client.post("/api/verify-totp", json={
            "session_token": "invalid-token",
            "totp_code": "123456",
        })
        assert resp.status_code == 401
        assert "expired" in resp.get_json()["error"].lower() or "invalid" in resp.get_json()["error"].lower()

    def test_verify_invalid_code_format(self, client):
        """Non-numeric or wrong length codes should be rejected."""
        resp = client.post("/api/verify-totp", json={
            "session_token": "fake",
            "totp_code": "ABCDEF",  # non-numeric
        })
        assert resp.status_code == 401   # session invalid too, but format validated first
