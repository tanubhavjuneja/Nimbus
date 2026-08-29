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
        return {"success": False, "error": f"No auto-fix available for: {check}"}

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
