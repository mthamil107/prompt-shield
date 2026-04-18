from __future__ import annotations

import pytest

from prompt_shield.output_scanners.code_injection import CodeInjectionScanner


@pytest.fixture
def scanner():
    return CodeInjectionScanner()


class TestCodeInjection:
    # ---- SQL injection ----

    def test_sql_drop_table(self, scanner):
        result = scanner.scan("DROP TABLE users")
        assert result.flagged is True
        assert "sql_injection" in result.categories

    def test_sql_union_injection(self, scanner):
        result = scanner.scan("' UNION SELECT username, password FROM admins --")
        assert result.flagged is True
        assert "sql_injection" in result.categories

    # ---- Shell injection ----

    def test_shell_rm_rf(self, scanner):
        result = scanner.scan("run this: ; rm -rf /important-data")
        assert result.flagged is True
        assert "shell_injection" in result.categories

    def test_python_os_system(self, scanner):
        result = scanner.scan("os.system('rm -rf /')")
        assert result.flagged is True
        assert "shell_injection" in result.categories

    # ---- XSS ----

    def test_xss_script_tag(self, scanner):
        result = scanner.scan('<script>alert("xss")</script>')
        assert result.flagged is True
        assert "xss" in result.categories

    def test_xss_event_handler(self, scanner):
        result = scanner.scan('<img onerror="javascript:alert(1)">')
        assert result.flagged is True
        assert "xss" in result.categories

    # ---- Path traversal ----

    def test_path_traversal(self, scanner):
        result = scanner.scan("open('../../../etc/passwd')")
        assert result.flagged is True
        assert "path_traversal" in result.categories

    # ---- SSRF ----

    def test_ssrf_localhost(self, scanner):
        result = scanner.scan("fetch('http://localhost:8080/admin')")
        assert result.flagged is True
        assert "ssrf" in result.categories

    def test_ssrf_cloud_metadata(self, scanner):
        result = scanner.scan(
            "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        )
        assert result.flagged is True
        assert "ssrf" in result.categories

    # ---- Deserialization ----

    def test_deserialization_pickle(self, scanner):
        result = scanner.scan("data = pickle.loads(untrusted_bytes)")
        assert result.flagged is True
        assert "deserialization" in result.categories

    # ---- Benign inputs ----

    def test_benign_code_passes(self, scanner):
        result = scanner.scan("def hello():\n    print('Hello, world!')\n    return 42")
        assert result.flagged is False

    def test_benign_sql_select_passes(self, scanner):
        result = scanner.scan("SELECT name FROM users WHERE id = 1")
        assert result.flagged is False

    # ---- Multi-category & field checks ----

    def test_multiple_categories(self, scanner):
        text = "DROP TABLE users; <script>alert(\"xss\")</script> os.system('whoami')"
        result = scanner.scan(text)
        assert result.flagged is True
        assert len(result.categories) >= 2
        assert result.confidence > 0.90

    def test_result_fields(self, scanner):
        result = scanner.scan("DROP TABLE accounts")
        assert result.scanner_id == "output_code_injection"
        assert result.flagged is True
        assert len(result.matches) >= 1
        assert result.matches[0].matched_text != ""
        assert result.metadata["severity"] in ("high", "critical")
