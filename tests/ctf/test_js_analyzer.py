"""Tests for JS Analyzer module."""
import pytest
from autopnex.ctf.js_analyzer import JSAnalyzer


@pytest.fixture
def analyzer():
    return JSAnalyzer()


class TestExtractApiEndpoints:
    """Test API endpoint extraction from JavaScript content."""

    def test_api_path_in_string(self, analyzer):
        js = '''const url = "/api/users/list";'''
        result = analyzer.extract_api_endpoints(js)
        assert "/api/users/list" in result

    def test_fetch_call(self, analyzer):
        js = '''fetch("/api/v1/auth/login").then(r => r.json());'''
        result = analyzer.extract_api_endpoints(js)
        assert "/api/v1/auth/login" in result

    def test_axios_get(self, analyzer):
        js = '''axios.get("/api/admin/users").then(res => console.log(res));'''
        result = analyzer.extract_api_endpoints(js)
        assert "/api/admin/users" in result

    def test_axios_post(self, analyzer):
        js = '''axios.post("/api/submit", data);'''
        result = analyzer.extract_api_endpoints(js)
        assert "/api/submit" in result

    def test_xhr_open(self, analyzer):
        js = '''xhr.open("GET", "/api/data/export");'''
        result = analyzer.extract_api_endpoints(js)
        assert "/api/data/export" in result

    def test_base_url_assignment(self, analyzer):
        js = '''const baseURL = "https://internal.example.com/api";'''
        result = analyzer.extract_api_endpoints(js)
        assert "https://internal.example.com/api" in result

    def test_multiple_endpoints_deduped(self, analyzer):
        js = '''
        fetch("/api/users");
        fetch("/api/users");
        axios.get("/api/users");
        '''
        result = analyzer.extract_api_endpoints(js)
        assert result.count("/api/users") == 1

    def test_empty_content(self, analyzer):
        result = analyzer.extract_api_endpoints("")
        assert result == []

    def test_no_api_paths(self, analyzer):
        js = '''console.log("hello world");'''
        result = analyzer.extract_api_endpoints(js)
        assert result == []

    def test_template_literal_api_path(self, analyzer):
        js = '''const url = "/api/items/123";'''
        result = analyzer.extract_api_endpoints(js)
        assert "/api/items/123" in result


class TestExtractSecrets:
    """Test secret/token extraction from JavaScript content."""

    def test_api_key(self, analyzer):
        js = '''const api_key = "sk_live_1234567890abcdef";'''
        result = analyzer.extract_secrets(js)
        assert len(result) >= 1
        assert any(s["type"] == "api_key" for s in result)

    def test_jwt_secret(self, analyzer):
        js = '''const jwt_secret = "my-super-secret-key-123";'''
        result = analyzer.extract_secrets(js)
        assert len(result) >= 1
        assert any(s["type"] == "jwt_secret" for s in result)

    def test_bearer_token(self, analyzer):
        js = '''headers: { "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature" }'''
        result = analyzer.extract_secrets(js)
        assert len(result) >= 1
        assert any(s["type"] == "bearer_token" for s in result)

    def test_aws_key(self, analyzer):
        js = '''const key = "AKIAIOSFODNN7EXAMPLE";'''
        result = analyzer.extract_secrets(js)
        assert len(result) >= 1
        assert any(s["type"] == "aws_key" for s in result)

    def test_password(self, analyzer):
        js = '''const password = "admin123456";'''
        result = analyzer.extract_secrets(js)
        assert len(result) >= 1
        assert any(s["type"] == "password" for s in result)

    def test_database_url(self, analyzer):
        js = '''const db = "mysql://root:pass@localhost/mydb";'''
        result = analyzer.extract_secrets(js)
        assert len(result) >= 1
        assert any(s["type"] == "database_url" for s in result)

    def test_no_secrets(self, analyzer):
        js = '''console.log("hello world");'''
        result = analyzer.extract_secrets(js)
        assert result == []

    def test_secret_has_context(self, analyzer):
        js = '''const api_key = "sk_live_1234567890abcdef";'''
        result = analyzer.extract_secrets(js)
        assert len(result) >= 1
        assert "context" in result[0]
        assert len(result[0]["context"]) > 0

    def test_deduplication(self, analyzer):
        js = '''
        const api_key = "sk_live_1234567890abcdef";
        const apikey = "sk_live_1234567890abcdef";
        '''
        result = analyzer.extract_secrets(js)
        values = [s["value"] for s in result]
        assert values.count("sk_live_1234567890abcdef") == 1


class TestDetectSourceMap:
    """Test source map detection."""

    def test_standard_source_map_comment(self, analyzer):
        js = '''
        function hello() { return "world"; }
        //# sourceMappingURL=app.js.map
        '''
        result = analyzer.detect_source_map(js)
        assert result == "app.js.map"

    def test_at_sign_source_map(self, analyzer):
        js = '''
        var x = 1;
        //@ sourceMappingURL=bundle.min.js.map
        '''
        result = analyzer.detect_source_map(js)
        assert result == "bundle.min.js.map"

    def test_full_url_source_map(self, analyzer):
        js = '''
        //# sourceMappingURL=https://cdn.example.com/maps/app.js.map
        '''
        result = analyzer.detect_source_map(js)
        assert result == "https://cdn.example.com/maps/app.js.map"

    def test_no_source_map(self, analyzer):
        js = '''function hello() { return "world"; }'''
        result = analyzer.detect_source_map(js)
        assert result is None

    def test_empty_content(self, analyzer):
        result = analyzer.detect_source_map("")
        assert result is None


class TestExtractRoutes:
    """Test frontend route extraction."""

    def test_react_route(self, analyzer):
        js = '''<Route path="/dashboard" component={Dashboard} />'''
        result = analyzer.extract_routes(js)
        assert "/dashboard" in result

    def test_react_route_exact(self, analyzer):
        js = '''<Route exact path="/admin/settings" component={Settings} />'''
        result = analyzer.extract_routes(js)
        assert "/admin/settings" in result

    def test_vue_router_path(self, analyzer):
        js = '''
        const routes = [
            { path: '/login', component: Login },
            { path: '/admin', component: Admin },
        ];
        '''
        result = analyzer.extract_routes(js)
        assert "/login" in result
        assert "/admin" in result

    def test_nextjs_pages(self, analyzer):
        js = '''import Page from "/pages/api/secret";'''
        result = analyzer.extract_routes(js)
        assert "/pages/api/secret" in result

    def test_no_routes(self, analyzer):
        js = '''console.log("no routes here");'''
        result = analyzer.extract_routes(js)
        assert result == []

    def test_deduplication(self, analyzer):
        js = '''
        { path: '/admin', component: Admin },
        { path: '/admin', component: AdminAlt },
        '''
        result = analyzer.extract_routes(js)
        assert result.count("/admin") == 1

    def test_mixed_frameworks(self, analyzer):
        js = '''
        <Route path="/react-page" component={Page} />
        { path: '/vue-page', component: VuePage },
        '''
        result = analyzer.extract_routes(js)
        assert "/react-page" in result
        assert "/vue-page" in result
