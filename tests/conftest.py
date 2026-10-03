import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def client(tmp_path, monkeypatch):
    import database

    monkeypatch.setattr(database, "DB_FILE", tmp_path / "adguard_logs.duckdb")
    from fastapi.testclient import TestClient

    import web_service

    with TestClient(web_service.app) as c:
        yield c
