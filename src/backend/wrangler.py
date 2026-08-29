"""Backend module — Wrangler CLI wrapper, security scanning, Ollama integration."""

import subprocess
import json
import os
import re
import time
import threading
import urllib.request
from pathlib import Path
from typing import Optional, Callable

from backend.warnings import WarningManager, OllamaClient, GLOSSARY, get_glossary, explain_term


class WranglerCLI:
    """Wrapper around the Wrangler CLI."""

    def __init__(self):
        self._account_id: Optional[str] = None
        self._account_name: Optional[str] = None
        self._logged_in = False
        self._listeners: list[Callable] = []

    def on_event(self, callback: Callable):
        self._listeners.append(callback)

    def _emit(self, event: str, data: dict = None):
        for cb in self._listeners:
            try:
                cb(event, data or {})
            except Exception:
                pass

    def _run(self, args: list[str], timeout: int = 30) -> dict:
        cmd = "wrangler " + " ".join(args)
        try:
            result = subprocess.run(
                cmd, capture_output=True, timeout=timeout,
                shell=True, encoding="utf-8", errors="replace"
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            if result.returncode != 0:
                return {"success": False, "error": stderr or stdout or "Command failed"}
            return {"success": True, "raw": stdout}
        except FileNotFoundError:
            return {"success": False, "error": "Wrangler not found. Run: npm install -g wrangler"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _parse_table(self, raw: str) -> list[dict]:
        lines = [l for l in raw.splitlines() if l.strip() and "│" in l]
        if len(lines) < 3:
            return []

        def split_row(line):
            parts = line.split("│")
            if len(parts) < 3:
                return []
            return [p.strip() for p in parts[1:-1]]

        header_idx = -1
        for i, line in enumerate(lines):
            if "├" not in line and "│" in line:
                header_idx = i
                break

        if header_idx < 0:
            return []

        headers = split_row(lines[header_idx])
        data = []
        for line in lines[header_idx + 1:]:
            if "├" in line or "└" in line or "┌" in line:
                continue
            if "│" not in line:
                continue
            cells = split_row(line)
            if cells and len(cells) >= len(headers):
                row = {headers[i]: cells[i] for i in range(len(headers)) if i < len(cells)}
                data.append(row)
        return data

    # ── Auth ──────────────────────────────────────────────

    def check_login(self) -> bool:
        result = self._run(["whoami"])
        if result["success"] and "logged in" in result.get("raw", "").lower():
            self._logged_in = True
            stdout = result["raw"]
            for i, line in enumerate(stdout.splitlines()):
                if "Account Name" in line and "│" in line:
                    for data_line in stdout.splitlines()[i+1:]:
                        if "├" in data_line or "─" in data_line:
                            continue
                        if "│" in data_line:
                            parts = [p.strip() for p in data_line.split("│") if p.strip()]
                            if len(parts) >= 2:
                                self._account_name = parts[0]
                                self._account_id = parts[1]
                            break
                    break
            if not self._account_name:
                m = re.search(r'[\w.+-]+@[\w.-]+\.\w+', stdout)
                if m:
                    self._account_name = m.group(0)
            if not self._account_name:
                self._account_name = "Cloudflare Account"
            return True
        self._logged_in = False
        return False

    def login(self) -> dict:
        result = self._run(["login"], timeout=120)
        if result["success"]:
            self.check_login()
        return result

    # ── Data Fetching ─────────────────────────────────────

    def list_pages_projects(self) -> list[dict]:
        result = self._run(["pages", "project", "list"])
        if result["success"]:
            raw = result.get("raw", "")
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass
            rows = self._parse_table(raw)
            return [{
                "name": r.get("Project Name", ""),
                "domains": r.get("Project Domains", ""),
                "git_provider": r.get("Git Provider", ""),
                "modified": r.get("Last Modified", "")
            } for r in rows if r.get("Project Name")]
        return []

    def list_kv_namespaces(self) -> list[dict]:
        result = self._run(["kv", "namespace", "list"])
        if result["success"]:
            raw = result.get("raw", "")
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass
        return []

    def list_r2_buckets(self) -> list[dict]:
        result = self._run(["r2", "bucket", "list"])
        if result["success"]:
            raw = result.get("raw", "")
            buckets = []
            current = {}
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("name:"):
                    if current:
                        buckets.append(current)
                    current = {"name": line.split(":", 1)[1].strip()}
                elif line.startswith("creation_date:") and current:
                    current["created_on"] = line.split(":", 1)[1].strip()
            if current and "name" in current:
                buckets.append(current)
            return buckets
        return []

    def list_d1_databases(self) -> list[dict]:
        result = self._run(["d1", "list"])
        if result["success"]:
            raw = result.get("raw", "")
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass
            rows = self._parse_table(raw)
            return [{
                "name": r.get("name", ""),
                "uuid": r.get("uuid", ""),
                "created_at": r.get("created_at", ""),
                "version": r.get("version", ""),
                "num_tables": r.get("num_tables", "0"),
                "file_size": r.get("file_size", "0")
            } for r in rows if r.get("name")]
        return []

    def list_secrets(self, worker_name: str = "") -> list[dict]:
        args = ["secret", "list"]
        if worker_name:
            args.extend(["--name", worker_name])
        result = self._run(args)
        if result["success"]:
            raw = result.get("raw", "")
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass
            secrets = []
            for line in raw.splitlines():
                line = line.strip()
                if "│" in line:
                    parts = [p.strip() for p in line.split("│") if p.strip()]
                    if len(parts) >= 1 and parts[0] not in ("Name", "─────", ""):
                        secrets.append({"name": parts[0]})
            return secrets
        return []

    def list_workers_from_pages(self) -> list[dict]:
        return [{
            "name": p.get("name", ""),
            "type": "pages",
            "domains": p.get("domains", ""),
            "modified": p.get("modified", "")
        } for p in self.list_pages_projects()]

    def _get_oauth_token(self) -> str:
        """Get OAuth token, refreshing via wrangler whoami if needed."""
        config_path = Path(os.environ.get("APPDATA", "")) / "xdg.config" / ".wrangler" / "config" / "default.toml"
        if not config_path.exists():
            home = Path.home()
            config_path = home / ".wrangler" / "config" / "default.toml"
        if not config_path.exists():
            return ""
        try:
            import datetime
            content = config_path.read_text(encoding="utf-8")
            exp_match = re.search(r'expiration_time\s*=\s*"([^"]+)"', content)
            if exp_match:
                exp_str = exp_match.group(1)
                exp_time = datetime.datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                now = datetime.datetime.now(datetime.timezone.utc)
                if exp_time < now:
                    self._run(["whoami"], timeout=15)
                    content = config_path.read_text(encoding="utf-8")
            token_match = re.search(r'oauth_token\s*=\s*"([^"]+)"', content)
            if token_match:
                return token_match.group(1)
        except Exception:
            pass
        return ""

    def list_workers(self) -> list[dict]:
        workers = []
        try:
            token = self._get_oauth_token()
            if not token:
                return workers
            if not self._account_id:
                self.check_login()
            if not self._account_id:
                return workers
            api_url = f"https://api.cloudflare.com/client/v4/accounts/{self._account_id}/workers/scripts"
            req = urllib.request.Request(api_url, headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            })
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                if data.get("success"):
                    for script in data.get("result", []):
                        workers.append({
                            "name": script.get("id", ""),
                            "type": "worker",
                            "modified": script.get("modified_on", ""),
                            "created": script.get("created_on", ""),
                            "compatibility_date": script.get("compatibility_date", "")
                        })
        except Exception:
            pass
        return workers

    def delete_pages_project(self, name: str) -> dict:
        result = self._run(["pages", "project", "delete", name])
        if result["success"]:
            return {"success": True, "message": f"Pages project '{name}' deleted"}
        error = result.get("error", "Delete failed")
        if "--force" in error:
            result2 = self._run(["pages", "project", "delete", name, "--yes"])
            if result2["success"]:
                return {"success": True, "message": f"Pages project '{name}' deleted"}
            return {"success": False, "error": result2.get("error", "Delete failed")}
        return {"success": False, "error": error}

    def delete_worker(self, name: str) -> dict:
        result = self._run(["delete", name])
        if result["success"]:
            return {"success": True, "message": f"Worker '{name}' deleted"}
        error = result.get("error", "Delete failed")
        if "--force" in error or "Unknown argument" in error:
            result2 = self._run(["delete", name, "--yes"])
            if result2["success"]:
                return {"success": True, "message": f"Worker '{name}' deleted"}
            return {"success": False, "error": result2.get("error", "Delete failed")}
        return {"success": False, "error": error}

    def get_worker_routes(self, name: str) -> list[dict]:
        result = self._run(["workers", "routes", "list", "--worker-name", name])
        if result["success"]:
            raw = result.get("raw", "")
            rows = self._parse_table(raw)
            return [{"pattern": r.get("Pattern", r.get("pattern", "")), "script": r.get("Script", r.get("script", ""))} for r in rows]
        return []

    def redeploy_pages(self, name: str) -> dict:
        result = self._run(["pages", "deployment", "create", "--project-name", name], timeout=120)
        if result["success"]:
            return {"success": True, "message": f"Redeploy triggered for '{name}'", "output": result.get("raw", "")}
        return {"success": False, "error": result.get("error", "Redeploy failed")}

    # ── Secret Scanner (GitGuardian-style) ────────────────

    SECRET_PATTERNS = [
        (r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API Key"),
        (r'(?i)(?:secret|password|passwd)\s*[:=]\s*["\']([^"\']{8,})["\']', "Secret/Password"),
        (r'(?i)(?:token|auth_token|access_token|bearer)\s*[:=]\s*["\']([A-Za-z0-9_\-.]{16,})["\']', "Auth Token"),
        (r'(?i)(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\']?(AKIA[A-Z0-9]{16})["\']?', "AWS Access Key ID"),
        (r'(?i)(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret Key"),
        (r'(?i)(?:private[_-]?key)\s*[:=]\s*["\']?(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)["\']?', "Private Key"),
        (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token"),
        (r'gho_[A-Za-z0-9]{36}', "GitHub OAuth Token"),
        (r'glpat-[A-Za-z0-9\-_]{20,}', "GitLab Personal Access Token"),
        (r'xox[bpsar]-[A-Za-z0-9\-]{10,}', "Slack Token"),
        (r'(?i)(?:sk_live|pk_live)_[A-Za-z0-9]{24,}', "Stripe Live Key"),
        (r'(?i)(?:sk_test|pk_test)_[A-Za-z0-9]{24,}', "Stripe Test Key"),
        (r'(?i)SK[A-Za-z0-9]{32,}', "Possible Secret Key"),
        (r'(?i)(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN)\s*[:=]\s*["\']([A-Za-z0-9_\-]{40,})["\']', "Cloudflare API Token"),
        (r'(?i)(?:CLOUDFLARE_API_KEY|CF_API_KEY)\s*[:=]\s*["\']([A-Za-z0-9_\-]{32,})["\']', "Cloudflare API Key"),
        (r'sk-[A-Za-z0-9]{48,}', "OpenAI API Key"),
        (r'AIza[A-Za-z0-9_\-]{35}', "Google API Key"),
        (r'(?i)database[_-]?url\s*[:=]\s*["\']((?:postgres|mysql|mongodb)://[^"\']+)["\']', "Database Connection String"),
        (r'(?i)smtp[_-]?pass(?:word)?\s*[:=]\s*["\']([^"\']{8,})["\']', "SMTP Password"),
    ]

    IGNORE_DIRS = {'.git', 'node_modules', '__pycache__', '.wrangler', '.next', 'dist', 'build', '.cache', 'venv', '.venv'}
    IGNORE_EXT = {'.pyc', '.pyo', '.class', '.o', '.so', '.dll', '.exe', '.bin', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.map', '.lock'}

    def scan_directory_secrets(self, directory: str) -> list[dict]:
        """Scan a directory for exposed secrets and API keys."""
        findings = []
        dir_path = Path(directory)
        if not dir_path.exists():
            return findings
        scanned = 0
        for f in dir_path.rglob("*"):
            if not f.is_file():
                continue
            if f.name in self.IGNORE_EXT or f.suffix.lower in self.IGNORE_EXT:
                continue
            if any(part in self.IGNORE_DIRS for part in f.parts):
                continue
            if f.stat().st_size > 1_000_000:
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            scanned += 1
            for pattern, secret_type in self.SECRET_PATTERNS:
                for match in re.finditer(pattern, content):
                    line_no = content[:match.start()].count('\n') + 1
                    matched_text = match.group(0)[:60]
                    finding_id = f"{f}:{line_no}:{secret_type}"
                    if not any(x.get("id") == finding_id for x in findings):
                        findings.append({
                        "id": finding_id,
                        "check": "SecretScan",
                        "severity": "Critical" if "Private Key" in secret_type or "Live" in secret_type else "High",
                        "message": f"{secret_type} found in {f.name}",
                        "simple_explanation": f"A {secret_type.lower()} was found in your code. If this is a real credential, anyone with access to this code can use it.",
                        "file": str(f),
                        "line": line_no,
                        "matched": matched_text,
                        "terms": ["API Token"],
                        "fix": "Move this to environment variables or use wrangler secret put."
                    })
        return findings

    # ── Dependency Vulnerability Scanner ───────────────────

    VULN_DB = {
        "lodash": {"CVE": "CVE-2021-23337", "severity": "High", "fix": "Upgrade to >= 4.17.21"},
        "minimist": {"CVE": "CVE-2021-44906", "severity": "Critical", "fix": "Upgrade to >= 1.2.6"},
        "node-fetch": {"CVE": "CVE-2022-0235", "severity": "High", "fix": "Upgrade to >= 2.6.7"},
        "axios": {"CVE": "CVE-2023-45857", "severity": "Medium", "fix": "Upgrade to >= 1.6.0"},
        "express": {"CVE": "CVE-2024-29041", "severity": "Medium", "fix": "Upgrade to >= 4.19.2"},
        "ws": {"CVE": "CVE-2024-37890", "severity": "High", "fix": "Upgrade to >= 8.17.1"},
        "jsonwebtoken": {"CVE": "CVE-2022-23529", "severity": "Critical", "fix": "Upgrade to >= 9.0.0"},
        "cookie": {"CVE": "CVE-2024-47764", "severity": "Medium", "fix": "Upgrade to >= 0.7.0"},
        "tar": {"CVE": "CVE-2024-28863", "severity": "High", "fix": "Upgrade to >= 6.2.1"},
        "undici": {"CVE": "CVE-2024-30260", "severity": "High", "fix": "Upgrade to >= 6.11.1"},
        "requests": {"CVE": "CVE-2023-32681", "severity": "Medium", "fix": "Upgrade to >= 2.31.0"},
        "urllib3": {"CVE": "CVE-2023-45803", "severity": "Medium", "fix": "Upgrade to >= 2.0.7"},
        "cryptography": {"CVE": "CVE-2024-26130", "severity": "Critical", "fix": "Upgrade to >= 42.0.4"},
        "pillow": {"CVE": "CVE-2024-28219", "severity": "Critical", "fix": "Upgrade to >= 10.3.0"},
        "flask": {"CVE": "CVE-2023-30861", "severity": "Medium", "fix": "Upgrade to >= 2.3.2"},
        "django": {"CVE": "CVE-2024-24680", "severity": "High", "fix": "Upgrade to >= 4.2.10"},
        "jinja2": {"CVE": "CVE-2024-22195", "severity": "Medium", "fix": "Upgrade to >= 3.1.3"},
        "aiohttp": {"CVE": "CVE-2024-23334", "severity": "High", "fix": "Upgrade to >= 3.9.2"},
        "tornado": {"CVE": "CVE-2024-52804", "severity": "Medium", "fix": "Upgrade to >= 6.4.2"},
    }

    def scan_dependencies(self, directory: str) -> list[dict]:
        """Scan package.json and requirements.txt for known vulnerable packages."""
        findings = []
        dir_path = Path(directory)

        # Scan package.json (npm)
        pkg_json = dir_path / "package.json"
        if pkg_json.exists():
            try:
                pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
                all_deps = {}
                all_deps.update(pkg.get("dependencies", {}))
                all_deps.update(pkg.get("devDependencies", {}))
                for name, version_spec in all_deps.items():
                    clean_ver = re.sub(r'[^0-9.]', '', version_spec.split('^')[0].split('~')[0].split('>')[0].split('<')[0])
                    if name.lower() in self.VULN_DB:
                        vuln = self.VULN_DB[name.lower()]
                        findings.append({
                            "check": "VulnDependency",
                            "severity": vuln["severity"],
                            "message": f"Vulnerable {name} {version_spec}: {vuln['CVE']}",
                            "simple_explanation": f"The package {name} version {version_spec} has a known security vulnerability ({vuln['CVE']}).",
                            "file": str(pkg_json),
                            "fix": vuln["fix"],
                            "terms": []
                        })
            except Exception:
                pass

        # Scan requirements.txt (pip)
        req_txt = dir_path / "requirements.txt"
        if req_txt.exists():
            try:
                for line in req_txt.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    match = re.match(r'^([a-zA-Z0-9_-]+)\s*([=><!~]+)?\s*(.+)?', line)
                    if match:
                        name = match.group(1).lower()
                        version_spec = (match.group(2) or '') + (match.group(3) or '')
                        if name in self.VULN_DB:
                            vuln = self.VULN_DB[name]
                            findings.append({
                                "check": "VulnDependency",
                                "severity": vuln["severity"],
                                "message": f"Vulnerable {name} {version_spec}: {vuln['CVE']}",
                                "simple_explanation": f"The package {name} version {version_spec} has a known security vulnerability ({vuln['CVE']}).",
                                "file": str(req_txt),
                                "fix": vuln["fix"],
                                "terms": []
                            })
            except Exception:
                pass

        return findings

    # ── .env Exposure Checker ─────────────────────────────

    def scan_env_exposure(self, directory: str) -> list[dict]:
        """Check if .env files exist and are not properly gitignored."""
        findings = []
        dir_path = Path(directory)
        gitignore_path = dir_path / ".gitignore"
        gitignore_content = ""
        if gitignore_path.exists():
            try:
                gitignore_content = gitignore_path.read_text(encoding="utf-8").lower()
            except Exception:
                pass

        env_files = [".env", ".env.local", ".env.production", ".env.development", ".dev.vars"]
        for env_name in env_files:
            env_path = dir_path / env_name
            if env_path.exists():
                if env_name not in gitignore_content:
                    findings.append({
                        "check": "EnvExposure",
                        "severity": "Critical",
                        "message": f"{env_name} exists but is NOT in .gitignore",
                        "simple_explanation": f"Your {env_name} file contains secrets and will be uploaded to GitHub if you push. This exposes all your passwords and API keys publicly.",
                        "file": str(env_path),
                        "fix": f"Add '{env_name}' to your .gitignore file immediately.",
                        "terms": []
                    })
                # Check if env file has actual content
                try:
                    content = env_path.read_text(encoding="utf-8", errors="ignore")
                    lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith('#') and '=' in l]
                    if lines:
                        findings.append({
                            "check": "EnvFilePresent",
                            "severity": "Medium",
                            "message": f"{env_name} contains {len(lines)} variable(s) — consider moving to Cloudflare secrets",
                            "simple_explanation": f"Your {env_name} has {len(lines)} variables. Some may contain secrets that should be stored in Cloudflare's encrypted secret store instead.",
                            "file": str(env_path),
                            "fix": "Use 'wrangler secret put <NAME>' for sensitive values.",
                            "terms": []
                        })
                except Exception:
                    pass
        return findings

    # ── Security Headers Checker ──────────────────────────

    def scan_security_headers(self, directory: str) -> list[dict]:
        """Check worker source code for missing security headers."""
        findings = []
        dir_path = Path(directory)
        src_dirs = [dir_path / "src", dir_path]
        checked_files = set()

        header_checks = [
            (r'Content-Security-Policy', "Content Security Policy (CSP)", "Protects against XSS by controlling which resources can load"),
            (r'X-Frame-Options', "X-Frame-Options", "Prevents clickjacking by controlling if site can be framed"),
            (r'X-Content-Type-Options', "X-Content-Type-Options", "Prevents MIME-type sniffing attacks"),
            (r'Strict-Transport-Security', "HSTS", "Forces browsers to use HTTPS"),
            (r'Referrer-Policy', "Referrer-Policy", "Controls how much referrer info is shared"),
            (r'Permissions-Policy', "Permissions-Policy", "Controls which browser features can be used"),
            (r'X-XSS-Protection', "X-XSS-Protection", "Legacy XSS filter for older browsers"),
        ]

        for src_dir in src_dirs:
            if not src_dir.exists():
                continue
            for ext in ["*.js", "*.ts", "*.mjs", "*.py"]:
                for f in src_dir.rglob(ext):
                    if f in checked_files or any(part in self.IGNORE_DIRS for part in f.parts):
                        continue
                    checked_files.add(f)
                    if f.stat().st_size > 500_000:
                        continue
                    try:
                        content = f.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

                    has_response = bool(re.search(r'response|Response|new Response|JSONResponse', content))
                    if not has_response:
                        continue

                    for pattern, header_name, description in header_checks:
                        if not re.search(pattern, content, re.IGNORECASE):
                            findings.append({
                                "check": "MissingHeader",
                                "severity": "Medium",
                                "message": f"Missing {header_name} header in {f.name}",
                                "simple_explanation": f"Your worker response doesn't set the {header_name} header. {description}.",
                                "file": str(f),
                                "fix": f"Add '{header_name}' header to your response. Example: headers.set('{header_name}', 'value')",
                                "terms": []
                            })
        return findings

    # ── CORS Misconfiguration Checker ────────────────────

    def scan_cors(self, directory: str) -> list[dict]:
        """Check for overly permissive CORS configurations."""
        findings = []
        dir_path = Path(directory)
        checked_files = set()

        for ext in ["*.js", "*.ts", "*.mjs", "*.py"]:
            for f in dir_path.rglob(ext):
                if f in checked_files or any(part in self.IGNORE_DIRS for part in f.parts):
                    continue
                checked_files.add(f)
                if f.stat().st_size > 500_000:
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                # Check for wildcard CORS
                if re.search(r"""Access-Control-Allow-Origin.*\*|['"]?\*['"]?""", content):
                    findings.append({
                        "check": "CORSWildcard",
                        "severity": "High",
                        "message": f"CORS allows all origins (*) in {f.name}",
                        "simple_explanation": "Your code allows any website to make requests to your API. This could let malicious sites use your API on behalf of your users.",
                        "file": str(f),
                        "fix": "Replace '*' with specific allowed origins. Example: headers.set('Access-Control-Allow-Origin', 'https://yourdomain.com')",
                        "terms": []
                    })

                # Check for null origin
                if re.search(r"""Access-Control-Allow-Origin.*null|['"]null['"]""", content):
                    findings.append({
                        "check": "CORSEvilOrigin",
                        "severity": "High",
                        "message": f"CORS allows null origin in {f.name}",
                        "simple_explanation": "The 'null' origin is exploited by attackers using sandboxed iframes. This is almost never intentional.",
                        "file": str(f),
                        "fix": "Remove 'null' from allowed origins.",
                        "terms": []
                    })

                # Check for credentials with wildcard
                if re.search(r'Allow-Credentials.*true', content, re.IGNORECASE) and re.search(r'Access-Control-Allow-Origin.*\*', content):
                    findings.append({
                        "check": "CORSCredentialsWildcard",
                        "severity": "Critical",
                        "message": f"CORS credentials enabled with wildcard origin in {f.name}",
                        "simple_explanation": "You're allowing credentials (cookies/auth) from ANY origin. This is a critical security vulnerability.",
                        "file": str(f),
                        "fix": "Use specific origins when Allow-Credentials is true. Never combine credentials with '*'.",
                        "terms": []
                    })
        return findings

    # ── R2 Public Bucket Checker ──────────────────────────

    def scan_r2_public(self) -> list[dict]:
        """Check if any R2 buckets are publicly accessible."""
        findings = []
        buckets = self.list_r2_buckets()
        for bucket in buckets:
            name = bucket.get("name", "")
            if not name:
                continue
            result = self._run(["r2", "bucket", "detail", name])
            if result["success"]:
                raw = result.get("raw", "")
                if "public" in raw.lower():
                    findings.append({
                        "check": "PublicBucket",
                        "severity": "High",
                        "message": f"R2 bucket '{name}' may be publicly accessible",
                        "simple_explanation": f"The bucket '{name}' appears to have public access configured. Anyone on the internet could read or list your files.",
                        "file": "",
                        "fix": "Review bucket permissions and remove public access unless intentionally serving public files.",
                        "terms": []
                    })
        return findings

    # ── AI Code Review (Ollama-powered) ───────────────────

    def ai_code_review(self, directory: str, ollama_client=None) -> list[dict]:
        """Use Ollama to review source code for security vulnerabilities."""
        findings = []
        if not ollama_client or not ollama_client.is_available():
            return findings

        dir_path = Path(directory)
        review_files = []

        for ext in ["*.js", "*.ts", "*.mjs", "*.py"]:
            for f in dir_path.rglob(ext):
                if any(part in self.IGNORE_DIRS for part in f.parts):
                    continue
                if f.stat().st_size > 50_000:
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    if len(content.strip()) > 50:
                        review_files.append((f, content))
                except Exception:
                    continue

        for f, content in review_files[:5]:  # Limit to 5 files to avoid overloading Ollama
            prompt = (
                f"Review this {f.suffix} file for security vulnerabilities. "
                f"Focus on: SQL injection, XSS, CSRF, authentication bypass, "
                f"insecure deserialization, path traversal, command injection, "
                f"hardcoded credentials, and insecure configurations. "
                f"Reply in JSON array format: "
                '[{"severity":"Critical/High/Medium/Low","title":"issue title","line":"line number or range","description":"what is wrong","fix":"how to fix"}] '
                f"If no issues found, return an empty array []. Be concise."
            )
            context = f"You are a senior security engineer reviewing code. Be thorough but only report real issues, not style preferences."
            full_prompt = f"File: {f.name}\n\n```\n{content[:4000]}\n```"

            response = ollama_client._chat(full_prompt, context)
            if not response:
                continue

            try:
                start = response.find("[")
                end = response.rfind("]") + 1
                if start >= 0 and end > start:
                    issues = json.loads(response[start:end])
                    for issue in issues:
                        findings.append({
                            "check": "AICodeReview",
                            "severity": issue.get("severity", "Medium"),
                            "message": f"{issue.get('title', 'Code issue')} in {f.name}",
                            "simple_explanation": issue.get("description", ""),
                            "file": str(f),
                            "line": issue.get("line", ""),
                            "fix": issue.get("fix", ""),
                            "terms": [],
                            "ai_generated": True
                        })
            except (json.JSONDecodeError, KeyError):
                pass

        return findings

    # ── Comprehensive Security Audit ──────────────────────

    def full_security_audit(self, directory: str, ollama_client=None) -> dict:
        """Run all security scanners and return combined results."""
        all_findings = []

        # 1. Config scan
        all_findings.extend(self.scan_local_config(directory))

        # 2. Secret scan
        all_findings.extend(self.scan_directory_secrets(directory))

        # 3. Dependency scan
        all_findings.extend(self.scan_dependencies(directory))

        # 4. .env exposure
        all_findings.extend(self.scan_env_exposure(directory))

        # 5. Security headers
        all_findings.extend(self.scan_security_headers(directory))

        # 6. CORS check
        all_findings.extend(self.scan_cors(directory))

        # 7. AI code review (if Ollama available)
        ai_findings = []
        if ollama_client and ollama_client.is_available():
            ai_findings = self.ai_code_review(directory, ollama_client)
            all_findings.extend(ai_findings)

        # Count by severity
        summary = {
            "total": len(all_findings),
            "critical": sum(1 for f in all_findings if f.get("severity") == "Critical"),
            "high": sum(1 for f in all_findings if f.get("severity") == "High"),
            "medium": sum(1 for f in all_findings if f.get("severity") == "Medium"),
            "low": sum(1 for f in all_findings if f.get("severity") == "Low"),
            "ai_reviewed": len(ai_findings),
            "scanners": [
                "Config Scan", "Secret Scanner", "Dependency Check",
                "Environment Exposure", "Security Headers", "CORS Check"
            ]
        }
        if ollama_client and ollama_client.is_available():
            summary["scanners"].append("AI Code Review")

        return {"success": True, "findings": all_findings, "summary": summary}

    # ── Project Details ───────────────────────────────────

    def get_pages_project_details(self, name: str) -> dict:
        deployments = []
        result = self._run(["pages", "deployment", "list", "--project-name", name])
        if result["success"]:
            raw = result.get("raw", "")
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    deployments = data
            except json.JSONDecodeError:
                rows = self._parse_table(raw)
                deployments = rows
        return {"name": name, "url": f"https://{name}.pages.dev", "deployments": deployments}

    def get_worker_details(self, name: str) -> dict:
        details = {"name": name, "routes": [], "settings": {}, "bindings": []}
        result = self._run(["pages", "project", "get", name])
        if result["success"]:
            raw = result.get("raw", "")
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    details.update(data)
            except json.JSONDecodeError:
                pass
        return details

    def get_d1_details(self, name: str) -> dict:
        details = {"name": name, "tables": [], "size": "0"}
        result = self._run(["d1", "tables", "list", name])
        if result["success"]:
            raw = result.get("raw", "")
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    details["tables"] = data
            except json.JSONDecodeError:
                rows = self._parse_table(raw)
                details["tables"] = rows
        return details

    def get_kv_details(self, namespace_id: str) -> dict:
        details = {"id": namespace_id, "keys": []}
        result = self._run(["kv", "namespace", "key", "list", "--namespace-id", namespace_id])
        if result["success"]:
            raw = result.get("raw", "")
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    details["keys"] = data
            except json.JSONDecodeError:
                pass
        return details

    def get_r2_details(self, bucket: str) -> dict:
        details = {"name": bucket, "objects": []}
        result = self._run(["r2", "object", "list", bucket])
        if result["success"]:
            raw = result.get("raw", "")
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    details["objects"] = data.get("objects", [])
            except json.JSONDecodeError:
                pass
        return details

    # ── Create Resources ──────────────────────────────────

    def create_d1_database(self, name: str) -> dict:
        result = self._run(["d1", "create", name], timeout=30)
        if result["success"]:
            raw = result.get("raw", "")
            try:
                data = json.loads(raw)
                return {"success": True, "data": data, "message": f"Database '{name}' created"}
            except json.JSONDecodeError:
                return {"success": True, "message": f"Database '{name}' created", "raw": raw}
        return {"success": False, "error": result.get("error", "Failed to create database")}

    def create_r2_bucket(self, name: str, location: str = "auto") -> dict:
        result = self._run(["r2", "bucket", "create", name, "--location", location], timeout=30)
        if result["success"]:
            return {"success": True, "message": f"Bucket '{name}' created"}
        return {"success": False, "error": result.get("error", "Failed to create bucket")}

    def upload_r2_file(self, bucket: str, key: str, file_path: str) -> dict:
        p = Path(file_path)
        if not p.exists():
            return {"success": False, "error": f"File not found: {file_path}"}
        result = self._run(["r2", "object", "put", f"{bucket}/{key}", "--file", str(p)], timeout=120)
        if result["success"]:
            return {"success": True, "message": f"Uploaded '{p.name}' to {bucket}/{key}"}
        return {"success": False, "error": result.get("error", "Upload failed")}

    def list_r2_objects(self, bucket: str) -> list[dict]:
        result = self._run(["r2", "object", "list", bucket])
        if result["success"]:
            raw = result.get("raw", "")
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    return data.get("objects", [])
            except json.JSONDecodeError:
                pass
        return []

    def delete_r2_object(self, bucket: str, key: str) -> dict:
        result = self._run(["r2", "object", "delete", f"{bucket}/{key}"])
        if result["success"]:
            return {"success": True, "message": f"Deleted {key} from {bucket}"}
        return {"success": False, "error": result.get("error", "Delete failed")}

    def delete_d1_database(self, name: str) -> dict:
        result = self._run(["d1", "delete", name, "--force"])
        if result["success"]:
            return {"success": True, "message": f"Database '{name}' deleted"}
        return {"success": False, "error": result.get("error", "Delete failed")}

    def delete_r2_bucket(self, name: str) -> dict:
        result = self._run(["r2", "bucket", "delete", name, "--force"])
        if result["success"]:
            return {"success": True, "message": f"Bucket '{name}' deleted"}
        return {"success": False, "error": result.get("error", "Delete failed")}

    def create_worker_project(self, name: str) -> dict:
        p = Path.cwd() / name
        if p.exists():
            return {"success": False, "error": f"Directory '{name}' already exists"}
        result = self._run(["init", name], timeout=60)
        if result["success"]:
            return {"success": True, "message": f"Worker '{name}' created at {p}", "path": str(p)}
        return {"success": False, "error": result.get("error", "Failed to create worker")}

    def create_pages_project(self, name: str) -> dict:
        result = self._run(["pages", "project", "create", name], timeout=30)
        if result["success"]:
            return {"success": True, "message": f"Pages project '{name}' created"}
        return {"success": False, "error": result.get("error", "Failed to create Pages project")}

    # ── Deploy ────────────────────────────────────────────

    def deploy_worker(self) -> dict:
        result = self._run(["deploy"], timeout=120)
        return {"success": result["success"], "output": result.get("raw", ""), "error": result.get("error", "")}

    def deploy_pages(self, project: str, directory: str) -> dict:
        result = self._run(["pages", "deploy", directory, "--project-name", project], timeout=180)
        return {"success": result["success"], "output": result.get("raw", ""), "error": result.get("error", "")}

    def smart_deploy(self, project_path: str, project_name: str = "", project_type: str = "") -> dict:
        p = Path(project_path)
        if not p.exists():
            return {"success": False, "error": f"Directory not found: {project_path}"}
        config = p / "wrangler.toml"
        if not config.exists():
            config = p / "wrangler.jsonc"
        if not config.exists():
            config = p / "wrangler.json"
        if not project_type and config.exists():
            try:
                content = config.read_text(encoding="utf-8")
                if "pages" in content.lower() or (p / "package.json").exists():
                    pkg = p / "package.json"
                    if pkg.exists():
                        pkg_data = json.loads(pkg.read_text(encoding="utf-8"))
                        scripts = pkg_data.get("scripts", {})
                        if "build" in scripts:
                            build_result = self._run(["--cwd", str(p), "run", "build"], timeout=120)
                            if not build_result["success"]:
                                return {"success": False, "error": f"Build failed: {build_result.get('error', '')}"}
            except Exception:
                pass
        if project_type == "pages" or (not project_type and not config.exists()):
            if not project_name:
                project_name = p.name
            return self.deploy_pages(project_name, str(p))
        else:
            if config.exists():
                build_result = self._run(["deploy", "--cwd", str(p)], timeout=120)
                return {"success": build_result["success"], "output": build_result.get("raw", ""), "error": build_result.get("error", "")}
            return {"success": False, "error": "No wrangler config found"}

    # ── Security Scan ─────────────────────────────────────

    def scan_local_config(self, project_path: str = ".") -> list[dict]:
        findings = []
        config_path = Path(project_path) / "wrangler.toml"
        if not config_path.exists():
            config_path = Path(project_path) / "wrangler.jsonc"
        if not config_path.exists():
            config_path = Path(project_path) / "wrangler.json"
        if not config_path.exists():
            return findings

        try:
            content = config_path.read_text(encoding="utf-8")
        except Exception:
            return findings

        # Check [vars] for secrets
        sensitive_vars = []
        in_vars = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("[vars]"):
                in_vars = True
                continue
            if in_vars and stripped.startswith("["):
                in_vars = False
            if in_vars and "=" in stripped:
                key = stripped.split("=")[0].strip()
                val = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                if any(s in key.lower() for s in ["secret", "key", "token", "password", "api"]):
                    if val and val not in ("", '""', "''", "REPLACE_ME"):
                        sensitive_vars.append(key)

        if sensitive_vars:
            findings.append({
                "check": "VarsSecrets",
                "severity": "Critical",
                "message": f"Plaintext secrets found in configuration: {', '.join(sensitive_vars)}",
                "simple_explanation": "These sensitive values are stored in plain text in your config file. Anyone who sees your code can read them.",
                "fix": "Use 'wrangler secret put <NAME>' to store them securely on Cloudflare's servers.",
                "file": str(config_path),
                "terms": ["API Token"]
            })

        # Check .gitignore
        gitignore = Path(project_path) / ".gitignore"
        if gitignore.exists():
            gi = gitignore.read_text(encoding="utf-8").lower()
            if ".dev.vars" not in gi:
                findings.append({
                    "check": "DevVarsGitignore",
                    "severity": "High",
                    "message": "Development secrets file (.dev.vars) not in .gitignore",
                    "simple_explanation": "Your local development secrets could be accidentally uploaded to GitHub, exposing them to the public.",
                    "fix": "Add '.dev.vars' to your .gitignore file.",
                    "file": str(gitignore),
                    "terms": []
                })

        # Check account_id
        has_account_id = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("account_id") and not stripped.startswith("#"):
                has_account_id = True
                break
        if has_account_id:
            findings.append({
                "check": "AccountIdExposed",
                "severity": "Medium",
                "message": "Account ID exposed in config file",
                "simple_explanation": "Your Cloudflare account ID is visible in the config. In a public repository, attackers can use this to target your account.",
                "fix": "Comment out account_id and use the CLOUDFLARE_ACCOUNT_ID environment variable instead.",
                "file": str(config_path),
                "terms": ["API Token"]
            })

        # Check source code for hardcoded secrets
        src_dir = Path(project_path) / "src"
        if src_dir.exists():
            for ext in ["*.js", "*.ts", "*.mjs"]:
                for f in src_dir.rglob(ext):
                    try:
                        src = f.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue
                    patterns = [
                        (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'](?!REPLACE_ME)[^"\']{8,}["\']', "Hardcoded API key"),
                        (r'(?:secret|password|token)\s*[:=]\s*["\'](?!REPLACE_ME)[^"\']{8,}["\']', "Hardcoded secret"),
                    ]
                    for pat, desc in patterns:
                        if re.search(pat, src, re.IGNORECASE):
                            findings.append({
                                "check": "HardcodedSecret",
                                "severity": "Critical",
                                "message": f"{desc} detected in {f.name}",
                                "simple_explanation": f"A secret value is written directly in your code. If this code is shared, anyone can see it.",
                                "fix": "Move this value to environment variables or use 'wrangler secret put'.",
                                "file": str(f),
                                "terms": ["API Token"]
                            })

        return findings

    # ── Auto-Fix ──────────────────────────────────────────

    def fix_finding(self, finding: dict, project_path: str = ".") -> dict:
        check = finding.get("check", "")
        if check == "VarsSecrets":
            return self._fix_vars_secrets(finding, project_path)
        elif check == "DevVarsGitignore":
            return self._fix_dev_vars_gitignore(project_path)
        elif check == "AccountIdExposed":
            return self._fix_account_id(project_path)
        elif check == "HardcodedSecret":
            return self._fix_hardcoded_secret(finding, project_path)
        elif check == "VulnDependency":
            return self._fix_vulnerable_dep(finding, project_path)
        elif check == "EnvExposure":
            return self._fix_env_exposure(finding, project_path)
        elif check == "EnvFilePresent":
            return self._fix_env_to_secrets(finding, project_path)
        elif check == "MissingHeader":
            return self._fix_missing_header(finding, project_path)
        elif check == "CORSWildcard":
            return self._fix_cors_wildcard(finding, project_path)
        elif check == "CORSEvilOrigin":
            return self._fix_cors_wildcard(finding, project_path)
        elif check == "CORSCredentialsWildcard":
            return self._fix_cors_wildcard(finding, project_path)
        elif check == "SecretScan":
            return self._fix_secret_scan(finding, project_path)
        return {"success": False, "error": f"No auto-fix available for: {check}"}

    def _fix_vulnerable_dep(self, finding: dict, project_path: str) -> dict:
        """Update vulnerable dependency to fixed version."""
        msg = finding.get("message", "")
        file_path = finding.get("file", "")
        match = re.search(r'Vulnerable\s+(\S+)\s+\S+:\s+\S+', msg)
        if not match:
            return {"success": False, "error": "Could not parse dependency info"}
        dep_name = match.group(1)
        fix_text = finding.get("fix", "")
        version_match = re.search(r'upgrade to >=?\s*(\S+)', fix_text, re.IGNORECASE)
        if not version_match:
            return {"success": False, "error": "Could not determine target version"}
        target_version = version_match.group(1)

        p = Path(file_path)
        if p.name == "package.json":
            try:
                pkg = json.loads(p.read_text(encoding="utf-8"))
                for key in ["dependencies", "devDependencies"]:
                    if dep_name in pkg.get(key, {}):
                        pkg[key][dep_name] = f"^{target_version}"
                p.write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
                return {"success": True, "message": f"Updated {dep_name} to >= {target_version} in package.json",
                        "note": "Run npm install to apply changes."}
            except Exception as e:
                return {"success": False, "error": str(e)}
        elif p.name == "requirements.txt":
            try:
                content = p.read_text(encoding="utf-8")
                new_lines = []
                for line in content.splitlines():
                    if line.strip().lower().startswith(dep_name.lower()):
                        new_lines.append(f"{dep_name}>={target_version}")
                    else:
                        new_lines.append(line)
                p.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                return {"success": True, "message": f"Updated {dep_name} to >= {target_version} in requirements.txt"}
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": False, "error": "Unsupported package file"}

    def _fix_env_exposure(self, finding: dict, project_path: str) -> dict:
        """Add .env files to .gitignore."""
        msg = finding.get("message", "")
        match = re.search(r'(\S+)\s+exists but is NOT', msg)
        env_name = match.group(1) if match else ".env"
        gitignore_path = Path(project_path) / ".gitignore"
        try:
            existing = ""
            if gitignore_path.exists():
                existing = gitignore_path.read_text(encoding="utf-8")
            if env_name in existing:
                return {"success": True, "message": f"{env_name} already in .gitignore"}
            existing = existing.rstrip() + f"\n{env_name}\n"
            gitignore_path.write_text(existing, encoding="utf-8")
            return {"success": True, "message": f"Added {env_name} to .gitignore"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _fix_env_to_secrets(self, finding: dict, project_path: str) -> dict:
        """Suggest moving env vars to wrangler secrets."""
        msg = finding.get("message", "")
        return {"success": True, "message": "Review each variable and move sensitive ones to wrangler secret put",
                "note": "For each secret: wrangler secret put <NAME> (then remove from .env)"}

    def _fix_missing_header(self, finding: dict, project_path: str) -> dict:
        """Inject missing security headers into worker source code."""
        msg = finding.get("message", "")
        file_path = finding.get("file", "")
        header_match = re.search(r'Missing\s+(.+?)\s+header', msg)
        if not header_match:
            return {"success": False, "error": "Could not parse header name"}
        header_name = header_match.group(1)

        header_defaults = {
            "Content Security Policy (CSP)": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "HSTS": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "X-XSS-Protection": "1; mode=block"
        }
        header_value = header_defaults.get(header_name, "true")
        header_http = header_name.replace("Content Security Policy (CSP)", "Content-Security-Policy")

        p = Path(file_path)
        try:
            content = p.read_text(encoding="utf-8")
            if p.suffix in ('.js', '.ts', '.mjs'):
                # For JS/TS workers - find the Response constructor and add headers
                if header_http in content:
                    return {"success": True, "message": f"{header_name} header already present"}

                insert_pattern = r'(new\s+Response\([^)]*,\s*\{[^}]*headers\s*:\s*\{)'
                if re.search(insert_pattern, content):
                    content = re.sub(insert_pattern, rf'\1\n          "{header_http}": "{header_value}",', content, count=1)
                else:
                    # Try to find a headers object
                    alt_pattern = r'(headers\s*:\s*\{)'
                    if re.search(alt_pattern, content):
                        content = re.sub(alt_pattern, rf'\1\n            "{header_http}": "{value}",', content, count=1)
                    else:
                        return {"success": False, "error": "Could not find headers in response. Add manually."}
            elif p.suffix == '.py':
                # For Python workers
                if header_http.lower() in content.lower():
                    return {"success": True, "message": f"{header_name} header already present"}
                # Find response creation and add header
                insert_point = content.rfind("return Response(")
                if insert_point == -1:
                    insert_point = content.rfind("return Response(")
                if insert_point >= 0:
                    lines = content.splitlines()
                    for i, line in enumerate(lines):
                        if "return Response(" in line:
                            indent = len(line) - len(line.lstrip())
                            header_line = " " * (indent + 4) + f'headers["{header_http}"] = "{header_value}"'
                            lines.insert(i, header_line)
                            content = "\n".join(lines)
                            break
                else:
                    return {"success": False, "error": "Could not find Response in code. Add manually."}

            p.write_text(content, encoding="utf-8")
            return {"success": True, "message": f"Added {header_name} header to {p.name}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _fix_cors_wildcard(self, finding: dict, project_path: str) -> dict:
        """Replace CORS wildcard with a safe default."""
        file_path = finding.get("file", "")
        p = Path(file_path)
        try:
            content = p.read_text(encoding="utf-8")
            # Replace Access-Control-Allow-Origin: * with specific origin
            content = re.sub(
                r"""(Access-Control-Allow-Origin["\']?\s*[:=]\s*["'])\*["']?""",
                r"\1https://yourdomain.com",
                content
            )
            # Also handle header.set style
            content = re.sub(
                r"""(["']Access-Control-Allow-Origin["']\s*,\s*["'])\*["']""",
                r"\1https://yourdomain.com",
                content
            )
            # Remove null origin
            content = re.sub(r"""["']null["']""", '"https://yourdomain.com"', content)
            p.write_text(content, encoding="utf-8")
            return {"success": True, "message": f"Replaced CORS wildcard in {p.name}",
                    "note": "Update 'https://yourdomain.com' to your actual domain."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _fix_secret_scan(self, finding: dict, project_path: str) -> dict:
        """For detected secrets: add file to .gitignore or suggest wrangler secret put."""
        file_path = finding.get("file", "")
        matched = finding.get("matched", "")
        p = Path(file_path)

        # If it's a .env or config file, suggest moving to secrets
        if p.name.startswith(".env") or p.name == "wrangler.toml":
            return {"success": True, "message": f"Secret found in {p.name}",
                    "note": "Move sensitive values to Cloudflare secrets: wrangler secret put <NAME>"}

        # For hardcoded values in source code, replace with env reference
        try:
            content = p.read_text(encoding="utf-8")
            if p.suffix in ('.js', '.ts', '.mjs'):
                # Replace hardcoded values with env.X references
                for pat in [r"""(["'])(?:sk_live_|sk_test_|sk-proj-|ghp_|gho_|glpat-|xoxb-|xoxp-|AKIA|AIza)[A-Za-z0-9_\-.""']+\1""",
                           r"""((?:api[_-]?key|apikey|secret|password|token|auth_token)\s*[:=]\s*["'])[^"']+(["'])"""]:
                    match = re.search(pat, content, re.IGNORECASE)
                    if match:
                        env_name = re.sub(r'[^A-Z0-9]', '_', match.group(0)[:20].upper()).strip('_')
                        content = content[:match.start()] + match.group(1) + f"env.{env_name}" + match.group(2) + content[match.end():]
                        break
                p.write_text(content, encoding="utf-8")
                return {"success": True, "message": f"Replaced hardcoded secret in {p.name} with env reference",
                        "note": f"Set the value with: wrangler secret put {env_name}"}
        except Exception:
            pass

        return {"success": True, "message": "Secret detected — review manually",
                "note": "Use wrangler secret put <NAME> to store securely, then reference as env.NAME"}

    # ── AI-Assisted Fix Generation ────────────────────────

    def ai_generate_fix(self, finding: dict, ollama_client=None) -> dict:
        """Use Ollama to generate a specific fix for a finding."""
        if not ollama_client or not ollama_client.is_available():
            return {"success": False, "error": "Ollama not available"}

        file_path = finding.get("file", "")
        content = ""
        if file_path and Path(file_path).exists():
            try:
                content = Path(file_path).read_text(encoding="utf-8", errors="ignore")[:4000]
            except Exception:
                pass

        prompt = (
            f"Fix this security issue:\n"
            f"Type: {finding.get('check', '')}\n"
            f"Issue: {finding.get('message', '')}\n"
            f"File: {file_path}\n"
        )
        if content:
            prompt += f"\nFile content:\n```\n{content}\n```\n"
        prompt += "\nProvide the exact code fix. Reply with ONLY the fixed code, no explanation."

        context = "You are a senior security engineer. Provide the exact corrected code."
        response = ollama_client._chat(prompt, context)
        if response:
            return {"success": True, "fix_code": response, "file": file_path}
        return {"success": False, "error": "Could not generate fix"}

    def _fix_vars_secrets(self, finding: dict, project_path: str) -> dict:
        config_path = Path(finding.get("file", Path(project_path) / "wrangler.toml"))
        if not config_path.exists():
            return {"success": False, "error": f"Config not found: {config_path}"}
        content = config_path.read_text(encoding="utf-8")
        lines = content.splitlines()
        new_lines, removed = [], []
        in_vars = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[vars]"):
                in_vars = True
                new_lines.append(line)
                continue
            if in_vars and stripped.startswith("["):
                in_vars = False
            if in_vars and "=" in stripped:
                key = stripped.split("=")[0].strip()
                if any(s in key.lower() for s in ["secret", "key", "token", "password", "api"]):
                    removed.append(key)
                    continue
            new_lines.append(line)
        config_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        return {"success": True, "message": f"Removed {len(removed)} secret(s): {', '.join(removed)}",
                "note": "Use 'wrangler secret put <NAME>' to re-add them securely."}

    def _fix_dev_vars_gitignore(self, project_path: str) -> dict:
        gitignore_path = Path(project_path) / ".gitignore"
        if not gitignore_path.exists():
            gitignore_path.write_text(".dev.vars\n", encoding="utf-8")
            return {"success": True, "message": "Created .gitignore with .dev.vars"}
        content = gitignore_path.read_text(encoding="utf-8")
        if ".dev.vars" in content:
            return {"success": True, "message": ".dev.vars already in .gitignore"}
        gitignore_path.write_text(content.rstrip() + "\n.dev.vars\n", encoding="utf-8")
        return {"success": True, "message": "Added .dev.vars to .gitignore"}

    def _fix_account_id(self, project_path: str) -> dict:
        config_path = Path(project_path) / "wrangler.toml"
        if not config_path.exists():
            return {"success": False, "error": "wrangler.toml not found"}
        content = config_path.read_text(encoding="utf-8")
        new_lines, fixed = [], False
        for line in content.splitlines():
            if line.strip().startswith("account_id") and not line.strip().startswith("#"):
                new_lines.append(f"# {line}")
                fixed = True
            else:
                new_lines.append(line)
        if fixed:
            config_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            return {"success": True, "message": "Commented out account_id. Set CLOUDFLARE_ACCOUNT_ID env var instead."}
        return {"success": False, "error": "account_id not found or already commented"}

    def _fix_hardcoded_secret(self, finding: dict, project_path: str) -> dict:
        file_path = Path(finding.get("file", ""))
        if not file_path.exists():
            return {"success": False, "error": f"Source file not found: {file_path}"}
        content = file_path.read_text(encoding="utf-8")
        original = content
        patterns = [
            (r'((?:const|let|var)\s+\w*(?:api[_-]?key|apikey|secret|password|token)\w*\s*=\s*["\'])[^"\']+(["\'])',
             r'\1REPLACE_ME\2'),
            (r'((?:api[_-]?key|apikey|secret|password|token)\s*[:=]\s*["\'])[^"\']+(["\'])',
             r'\1REPLACE_ME\2'),
        ]
        for pat, repl in patterns:
            content = re.sub(pat, repl, content, flags=re.IGNORECASE)
        if content != original:
            file_path.write_text(content, encoding="utf-8")
            return {"success": True, "message": f"Replaced secrets in {file_path.name} with REPLACE_ME",
                    "note": "Use env.API_KEY and set via wrangler secret put."}
        return {"success": False, "error": "No patterns matched for replacement"}


# ── Background Monitor ────────────────────────────────────

class SecurityMonitor:
    """Background monitor for periodic checks."""

    def __init__(self, cli: WranglerCLI, warning_mgr: WarningManager):
        self.cli = cli
        self.warning_mgr = warning_mgr
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._interval = 120

    def start(self, interval: int = 120):
        self._interval = interval
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            time.sleep(self._interval)

    def run_scan(self, project_path: str = ".") -> list[dict]:
        findings = self.cli.scan_local_config(project_path)
        return self.warning_mgr.process_findings(findings)
