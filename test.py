import pytest
import sqlite3
import os
from app import app

@pytest.fixture(autouse=True)
def clean_db():
    """Ensure database has a clean test user state."""
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username = ?", ("testuser",))
    conn.commit()
    conn.close()

@pytest.fixture
def client():
    app.config["TESTING"] = True
    # Disable CSRF checks or keys if needed, but in our case it's clean
    with app.test_client() as client:
        yield client

def test_home_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200

def test_export_csv_redirects_unauthenticated(client):
    response = client.get("/export")
    assert response.status_code == 302
    assert "/login" in response.location

def test_register_and_login_flow(client):
    # 1. Register analyst account
    reg_response = client.post("/register", data={
        "username": "testuser",
        "password": "password123"
    }, follow_redirects=True)
    assert reg_response.status_code == 200
    assert b"Registration successful" in reg_response.data

    # 2. Login analyst account
    login_response = client.post("/login", data={
        "username": "testuser",
        "password": "password123"
    }, follow_redirects=True)
    assert login_response.status_code == 200
    assert b"Logout" in login_response.data  # Navbar indicates logged in

    # 3. Request export CSV
    export_response = client.get("/export")
    assert export_response.status_code == 200
    assert "text/csv" in export_response.content_type
    assert b"indicator" in export_response.data