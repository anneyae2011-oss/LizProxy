import asyncio
import os
import tempfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.database import create_database
from backend.main import normalize_target_api_url
from backend.rp_api import rp_router


def run(coro):
    return asyncio.run(coro)


def test_rp_user_bio_persists_serverside():
    async def scenario():
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.close()
        db = create_database(database_path=tmp.name)
        try:
            await db.initialize()

            created = await db.create_rp_user(
                "u-bio-1", "bio_user_1", "hash", None, "first bio"
            )
            assert created is True

            user = await db.get_rp_user_by_id("u-bio-1")
            assert user is not None
            assert user.bio == "first bio"

            updated = await db.update_rp_user_profile(
                "u-bio-1", "bio_user_1", None, "updated bio"
            )
            assert updated is True

            updated_user = await db.get_rp_user_by_id("u-bio-1")
            assert updated_user is not None
            assert updated_user.bio == "updated bio"
        finally:
            await db.close()
            os.unlink(tmp.name)

    run(scenario())


def test_admin_target_api_url_normalizes_to_v1():
    assert normalize_target_api_url("https://api.openai.com") == "https://api.openai.com/v1"
    assert normalize_target_api_url("https://api.openai.com/") == "https://api.openai.com/v1"
    assert normalize_target_api_url("https://api.openai.com/v1") == "https://api.openai.com/v1"
    assert normalize_target_api_url("https://api.openai.com/v1/") == "https://api.openai.com/v1"


def test_rp_profile_bio_roundtrip_via_api():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    db = create_database(database_path=tmp.name)
    run(db.initialize())

    app = FastAPI()
    app.include_router(rp_router)
    app.state.db = db

    try:
        with TestClient(app) as client:
            username = "api_bio_user"
            password = "pass1234"

            register_res = client.post(
                "/api/rp/register",
                json={"username": username, "password": password, "bio": "initial bio"},
            )
            assert register_res.status_code == 200
            token = register_res.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}

            update_res = client.put(
                "/api/rp/profile",
                json={"username": username, "bio": "updated via api", "avatar": None},
                headers=headers,
            )
            assert update_res.status_code == 200

            profile_res = client.get("/api/rp/profile", headers=headers)
            assert profile_res.status_code == 200
            profile = profile_res.json()
            assert profile["username"] == username
            assert profile["bio"] == "updated via api"
    finally:
        run(db.close())
        os.unlink(tmp.name)
