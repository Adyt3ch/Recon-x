"""Unit tests for OpenAPI/Swagger specification parsing and API discovery."""

from reconx.modules.fingerprint import parse_openapi_spec


def test_parse_openapi_v3_json():
    spec_json = """{
      "openapi": "3.0.0",
      "info": {"title": "Sample API", "version": "1.0.0"},
      "paths": {
        "/api/v1/users": {
          "get": {
            "summary": "List users",
            "parameters": [
              {"name": "page", "in": "query"},
              {"name": "limit", "in": "query"}
            ]
          },
          "post": {
            "summary": "Create user"
          }
        },
        "/api/v1/users/{id}": {
          "get": {
            "parameters": [{"name": "id", "in": "path"}]
          },
          "delete": {}
        }
      }
    }"""
    endpoints = parse_openapi_spec(spec_json)
    assert len(endpoints) == 4

    paths = [ep[1] for ep in endpoints]
    methods = [ep[0] for ep in endpoints]

    assert "/api/v1/users" in paths
    assert "/api/v1/users/{id}" in paths
    assert "GET" in methods
    assert "POST" in methods
    assert "DELETE" in methods

    # Check parameter extraction
    user_get = next(ep for ep in endpoints if ep[0] == "GET" and ep[1] == "/api/v1/users")
    assert user_get[2] == ["page", "limit"]


def test_parse_swagger_v2_yaml():
    spec_yaml = """
swagger: "2.0"
info:
  title: "Petstore"
  version: "1.0.0"
paths:
  /pets:
    get:
      parameters:
        - name: tags
          in: query
    post:
      summary: Add pet
"""
    endpoints = parse_openapi_spec(spec_yaml)
    assert len(endpoints) == 2
    assert endpoints[0][0] == "GET"
    assert endpoints[0][1] == "/pets"
    assert endpoints[0][2] == ["tags"]
    assert endpoints[1][0] == "POST"


def test_parse_invalid_or_soft_404_text():
    # HTML 404 page should return 0 endpoints safely
    html_page = "<html><head><title>404 Not Found</title></head><body>Not found</body></html>"
    endpoints = parse_openapi_spec(html_page)
    assert endpoints == []
