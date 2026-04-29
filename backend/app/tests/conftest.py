import os

import pytest
from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = "sqlite:///./test_evidence_collector.db"

from app.main import app  # noqa: E402


@pytest.fixture
def client():
    return TestClient(app)
