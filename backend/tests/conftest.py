import os
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_tmp = tempfile.mkdtemp(prefix="ntdcp_test_")
os.environ["NTDCP_RUNTIME_DIR"] = _tmp
os.environ["NTDCP_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["NTDCP_OLLAMA_BASE_URL"] = "http://127.0.0.1:9"  # nothing listens here


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def demo_loaded(client):
    r = client.post("/api/demo/load")
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def cfg():
    from app.core.config import AnalysisSettings
    return AnalysisSettings()
