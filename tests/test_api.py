import pytest

READ_ROUTES = [
    "/api/stats",
    "/api/query-log-summary",
    "/api/domain-summary",
    "/api/base-domain-summary",
    "/api/ignored-domains",
    "/api/dashboard/headline",
    "/api/dashboard/queries-over-time",
    "/api/dashboard/first-seen",
    "/api/dashboard/top-filter-rules",
    "/api/dashboard/top-blocked-clients",
    "/api/dashboard/top-blocked-domains",
    "/api/dashboard/query-types",
    "/api/dashboard/suspicious-subdomains",
    "/api/findings",
]


@pytest.mark.parametrize("route", READ_ROUTES)
def test_read_routes_answer_on_an_empty_database(client, route):
    assert client.get(route).status_code == 200


def test_ignored_domain_round_trip(client):
    added = client.post("/api/ignored-domains", json={"domain": "ads.example.com", "notes": "test"})
    assert added.json()["success"] is True
    again = client.post("/api/ignored-domains", json={"domain": "ads.example.com"})
    assert again.json()["success"] is False
    listed = client.get("/api/ignored-domains").json()
    assert [d["domain"] for d in listed["domains"]] == ["ads.example.com"]
    removed = client.delete("/api/ignored-domains/ads.example.com")
    assert removed.json()["success"] is True
    missing = client.delete("/api/ignored-domains/ads.example.com")
    assert missing.json()["success"] is False
