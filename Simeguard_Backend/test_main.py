"""Run with:  pip install pytest httpx  &&  pytest -q
Uses a throw-away SQLite file and DEMO_MODE=1 so the demo logins exist."""
import os, tempfile

os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["DEMO_MODE"] = "1"
os.environ["SECRET_KEY"] = "test-secret"
os.environ["MAX_PER_UNIT"] = "4"

import pytest
from fastapi.testclient import TestClient
import main

KEY = {"X-API-Key": "dev-webhook-key"}


@pytest.fixture(scope="module")
def client():
    with TestClient(main.app) as c:   # `with` runs the lifespan (creates tables, seeds demo data)
        yield c


@pytest.fixture(scope="module")
def admin(client):
    r = client.post("/api/login", json={"username": "admin", "password": "admin123"})
    return {"Authorization": f"Bearer {r.json()['token']}"}


# ---------- units ----------
@pytest.mark.parametrize("raw,n", [("12", 12), ("no 12", 12), ("No. 12, Lorong 2", 12), ("Lorong 2, No 12", 12),
                                    ("0", None), ("61", None), ("abc", None), ("", None)])
def test_parse_unit(raw, n):
    assert main.parse_unit(raw) == n


@pytest.mark.parametrize("n,street", [(1, "Lorong 1"), (10, "Lorong 1"), (11, "Lorong 2"), (30, "Lorong 2"),
                                       (31, "Lorong 3"), (40, "Lorong 3"), (41, "Lorong 4"), (60, "Lorong 4")])
def test_lorong_matches_site_plan(n, street):
    assert main.lorong_of(n) == street


def test_demo_units_were_corrected(client, admin):
    units = {r["name"]: r["unit_number"] for r in client.get("/api/residents", headers=admin).json()["residents"]}
    assert units["Priya Nair"] == "No. 21, Lorong 2"
    assert units["Lim Wei Jie"] == "No. 8, Lorong 1"


def test_rejects_unit_outside_plan(client, admin):
    r = client.post("/api/residents", headers=admin, json={"name": "X", "phone": "0100000001", "unit_number": "61"})
    assert r.status_code == 400


def test_rejects_wrong_street(client, admin):
    r = client.post("/api/residents", headers=admin, json={"name": "X", "phone": "0100000002", "unit_number": "No. 55, Lorong 9"})
    assert r.status_code == 400


def test_rejects_street_prefix_match(client, admin):
    r = client.post("/api/residents", headers=admin, json={"name": "X", "phone": "0100000003", "unit_number": "No. 5, Lorong 10"})
    assert r.status_code == 400


def test_unit_cap(client, admin):
    for i in range(main.MAX_PER_UNIT):
        r = client.post("/api/residents", headers=admin,
                        json={"name": f"P{i}", "phone": f"0123000{i:03d}", "unit_number": "No. 55, Lorong 4"})
        assert r.status_code == 200, r.text
        assert r.json()["unit_number"] == "No. 55, Lorong 4"
    r = client.post("/api/residents", headers=admin, json={"name": "Extra", "phone": "0129999999", "unit_number": "55"})
    assert r.status_code == 409
    full = [u for u in client.get("/api/units", headers=admin).json()["units"] if u["unit"] == "No. 55, Lorong 4"][0]
    assert full["count"] == main.MAX_PER_UNIT


def test_units_endpoint_lists_all_60(client, admin):
    assert len(client.get("/api/units", headers=admin).json()["units"]) == 60


# ---------- webhook validation ----------
def test_webhook_needs_key(client):
    assert client.post("/api/ai_webhook", json={"type": "lost_pet", "location": "Main Gate"}).status_code == 401


def test_webhook_rejects_bad_type_and_location(client):
    assert client.post("/api/ai_webhook", headers=KEY, json={"type": "ufo", "location": "Main Gate"}).status_code == 422
    assert client.post("/api/ai_webhook", headers=KEY, json={"type": "lost_pet", "location": "Mars"}).status_code == 422
    bad_img = {"type": "lost_pet", "location": "Main Gate", "image_url": "javascript:alert(1)"}
    assert client.post("/api/ai_webhook", headers=KEY, json=bad_img).status_code == 422


def test_webhook_debounce(client):
    body = {"type": "trespasser", "location": "Lorong 3"}
    assert client.post("/api/ai_webhook", headers=KEY, json=body).json()["status"] == "success"
    assert client.post("/api/ai_webhook", headers=KEY, json=body).json()["status"] == "ignored"


# ---------- routing / prediction ----------
def test_astar_route():
    route = main.route_to_exit("Lorong 4 West", "suspicious_person")
    assert route["path"][0] == "Lorong 4 West" and route["path"][-1] in main.EXITS and route["eta_seconds"] > 0


def test_prediction_only_uses_connected_cameras():
    traj = main.build_trajectory("suspicious_person", [("Side Gate", "t1"), ("Lorong 3", "t2")])
    assert traj["predicted_next_zone"] == "Lorong 2"            # the only onward link from Lorong 3


def test_graph_hops():
    assert main.graph_hops("Main Gate", "Main Gate") == 0
    assert main.graph_hops("Main Gate", "Lorong 1") == 1
    assert main.graph_hops("Main Gate", "Nowhere") == float("inf")


# ---------- tracks ----------
def test_resolved_sightings_do_not_leak_into_new_track(client, admin):
    client.post("/api/ai_webhook", headers=KEY, json={"type": "suspicious_person", "location": "Side Gate"})
    feed = client.get("/api/security_feed", headers=admin).json()["alerts"]
    first = [a for a in feed if a["type"] == "suspicious_person" and a["location"] == "Side Gate"][0]
    client.put(f"/api/resolve_alert/{first['id']}", headers=admin)
    client.post("/api/ai_webhook", headers=KEY, json={"type": "suspicious_person", "location": "Lorong 3"})
    feed = client.get("/api/security_feed", headers=admin).json()["alerts"]
    newest = [a for a in feed if a["type"] == "suspicious_person" and a["location"] == "Lorong 3"][0]
    assert newest["trajectory"]["total_sightings"] == 1


def test_two_vehicles_are_two_tracks(client, admin):
    for plate, cam in (("AAA 111", "Main Gate"), ("BBB 222", "Side Gate")):
        client.post("/api/ai_webhook", headers=KEY, json={"type": "unregistered_vehicle", "location": cam, "plate_number": plate})
    feed = client.get("/api/security_feed", headers=admin).json()["alerts"]
    for plate in ("AAA 111", "BBB 222"):
        a = [x for x in feed if x["plate_number"] == plate][0]
        assert a["trajectory"]["total_sightings"] == 1


# ---------- auth ----------
def test_ws_ticket_is_not_a_login_token(client, admin):
    ticket = client.get("/api/ws_ticket", headers=admin).json()["ticket"]
    assert client.get("/api/me", headers={"Authorization": f"Bearer {ticket}"}).status_code == 401


def test_cameras_endpoint(client):
    cams = client.get("/api/cameras", headers=KEY).json()["cameras"]
    assert {c["name"] for c in cams} == set(main.CAMERA_NETWORK)
    assert client.get("/api/cameras").status_code == 401

# ---------- undo, stale alerts, stats ----------
from datetime import timedelta


def _open_ids(client, admin):
    return {a["id"] for a in client.get("/api/security_feed", headers=admin).json()["alerts"]}


def test_resolve_then_undo(client, admin):
    client.post("/api/ai_webhook", headers=KEY, json={"type": "tailgating", "location": "Lorong 2", "plate_number": "UNDO 1"})
    feed = client.get("/api/security_feed", headers=admin).json()["alerts"]
    iid = [a for a in feed if a["plate_number"] == "UNDO 1"][0]["id"]
    assert client.put(f"/api/resolve_alert/{iid}", headers=admin).status_code == 200
    assert iid not in _open_ids(client, admin)
    assert client.put(f"/api/reopen_alert/{iid}", headers=admin).status_code == 200
    assert iid in _open_ids(client, admin)
    assert client.put(f"/api/reopen_alert/{iid}", headers=admin).status_code == 409   # already open


def test_undo_restores_a_missing_pet(client, admin):
    owner = client.get("/api/residents", headers=admin).json()["residents"][0]["id"]
    pid = client.post("/api/lost_pets", headers=admin, json={
        "resident_id": owner, "pet_name": "Milo", "species": "Cat", "pet_image_url": "", "last_seen_location": "Community Park"}).json()["pet_id"]
    feed = client.get("/api/security_feed", headers=admin).json()["alerts"]
    iid = [a for a in feed if a["pet_id"] == pid][0]["id"]
    client.put(f"/api/resolve_alert/{iid}", headers=admin)
    assert pid not in {p["pet_id"] for p in client.get("/api/lost_pets", headers=admin).json()["missing_pets"]}
    client.put(f"/api/reopen_alert/{iid}", headers=admin)
    assert pid in {p["pet_id"] for p in client.get("/api/lost_pets", headers=admin).json()["missing_pets"]}


def test_stale_cleanup_never_touches_pets(client, admin):
    old = main.now_local() - timedelta(hours=main.STALE_HOURS + 5)
    with main.SessionLocal() as db:
        person = main.Incident(type="trespasser", location="Lorong 4 East", status="open", timestamp=old)
        pet = main.Incident(type="lost_pet", location="Lorong 1", status="open", timestamp=old, pet_id=999999)
        db.add_all([person, pet])
        db.commit()
        person_id, pet_id = person.id, pet.id
    assert client.get("/api/stats", headers=admin).json()["stale_count"] >= 1
    assert client.put("/api/resolve_stale", headers=admin).json()["resolved"] >= 1
    with main.SessionLocal() as db:
        assert db.get(main.Incident, person_id).status == "resolved"
        assert db.get(main.Incident, person_id).resolved_by == "admin"
        assert db.get(main.Incident, pet_id).status == "open"
        db.delete(db.get(main.Incident, pet_id))
        db.commit()


def test_auto_resolve_marks_resolver_as_auto(client):
    old = main.now_local() - timedelta(hours=main.STALE_HOURS + 1)
    with main.SessionLocal() as db:
        inc = main.Incident(type="suspicious_person", location="Lorong 2", status="open", timestamp=old)
        db.add(inc)
        db.commit()
        iid = inc.id
    main.auto_resolve_once()
    with main.SessionLocal() as db:
        assert db.get(main.Incident, iid).resolved_by == "auto"


def test_stats_shape(client, admin):
    s = client.get("/api/stats", headers=admin).json()
    assert set(s) == {"alerts_last_hour", "oldest_open_minutes", "stale_count", "stale_hours"}
    assert client.get("/api/stats").status_code == 401


def test_resolve_unknown_alert_is_404(client, admin):
    assert client.put("/api/resolve_alert/999999", headers=admin).status_code == 404


def test_delete_resident_removes_pets_and_login(client, admin):
    rid = client.post("/api/residents", headers=admin,
                      json={"name": "Temp Owner", "phone": "0198887777", "unit_number": "No. 3, Lorong 1"}).json()["resident_id"]
    pid = client.post("/api/lost_pets", headers=admin, json={
        "resident_id": rid, "pet_name": "Tempo", "species": "Cat", "pet_image_url": "",
        "last_seen_location": "Main Gate"}).json()["pet_id"]
    assert client.delete(f"/api/residents/{rid}", headers=admin).status_code == 200
    assert pid not in {p["pet_id"] for p in client.get("/api/lost_pets", headers=admin).json()["missing_pets"]}
    assert all(a["pet_id"] != pid for a in client.get("/api/security_feed", headers=admin).json()["alerts"])