"""Nimbus — Cloudflare Security Dashboard Desktop App."""

import sys
import json
import subprocess
import os
import urllib.request
from pathlib import Path
from PySide6.QtWidgets import QApplication, QFileDialog
from PySide6.QtCore import QObject, Slot, QUrl, QThread, Signal, QTimer
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebChannel import QWebChannel

from backend.wrangler import WranglerCLI, SecurityMonitor
from backend.warnings import WarningManager, OllamaClient, GLOSSARY, get_glossary, explain_term

FRONTEND_DIR = Path(__file__).parent / "frontend"
INDEX_HTML = FRONTEND_DIR / "index.html"


class Worker(QThread):
    """Runs a callable in a background thread, emits result via signal."""
    finished = Signal(str, str)  # (call_id, json_result)

    def __init__(self, call_id: str, func, *args, **kwargs):
        super().__init__()
        self.call_id = call_id
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            if isinstance(result, str):
                self.finished.emit(self.call_id, result)
            else:
                self.finished.emit(self.call_id, json.dumps(result))
        except Exception as e:
            self.finished.emit(self.call_id, json.dumps({"success": False, "error": str(e)}))


class Bridge(QObject):
    """Python bridge — heavy operations run in QThread workers."""

    _CONFIG_DIR = Path(os.environ.get("APPDATA", "~")) / ".cloudguard"
    _CONFIG_FILE = _CONFIG_DIR / "config.json"
    _CACHE_FILE = _CONFIG_DIR / "project_cache.json"

    def __init__(self, cli: WranglerCLI, monitor: SecurityMonitor,
                 warning_mgr: WarningManager, ollama: OllamaClient, parent=None):
        super().__init__(parent)
        self.cli = cli
        self.monitor = monitor
        self.warning_mgr = warning_mgr
        self.ollama = ollama
        self._workers: list[Worker] = []
        self._pending: dict[str, callable] = {}
        self._main_window = None
        self._config = self._load_config()
        # Load saved Ollama model from config
        saved_model = self._config.get("settings", {}).get("ollama_model", "")
        if saved_model:
            self.ollama._model = saved_model
        saved_url = self._config.get("settings", {}).get("ollama_url", "")
        if saved_url:
            self.ollama.base_url = saved_url

    def set_main_window(self, win):
        self._main_window = win

    def _load_config(self) -> dict:
        try:
            if self._CONFIG_FILE.exists():
                return json.loads(self._CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {"local_paths": {}, "settings": {}}

    def _save_config(self):
        try:
            self._CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            self._CONFIG_FILE.write_text(json.dumps(self._config, indent=2, default=str), encoding="utf-8")
        except Exception:
            pass

    def _load_cache(self) -> dict:
        try:
            if self._CACHE_FILE.exists():
                return json.loads(self._CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    def _save_cache(self, data: dict):
        try:
            self._CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            self._CACHE_FILE.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        except Exception:
            pass

    def _run_worker(self, call_id: str, func, *args, **kwargs):
        """Run func in a background thread, store callback for JS to poll."""
        w = Worker(call_id, func, *args, **kwargs)
        self._workers.append(w)
        w.finished.connect(self._on_worker_done)
        w.start()
        return json.dumps({"success": True, "call_id": call_id})

    def _on_worker_done(self, call_id: str, result: str):
        self._pending[call_id] = result

    @Slot(str, result=str)
    def poll_result(self, call_id: str) -> str:
        """JS polls this to get async results."""
        if call_id in self._pending:
            result = self._pending.pop(call_id)
            return result
        return json.dumps({"success": False, "pending": True})

    @Slot(result=str)
    def check_login(self) -> str:
        try:
            logged_in = self.cli.check_login()
            return json.dumps({"success": True, "data": {
                "logged_in": logged_in,
                "account": self.cli._account_name or ""
            }})
        except Exception:
            return json.dumps({"success": True, "data": {"logged_in": False, "account": ""}})

    @Slot(result=str)
    def login(self) -> str:
        try:
            proc = subprocess.Popen(
                "wrangler login", shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                encoding="utf-8", errors="replace"
            )
            try:
                stdout, stderr = proc.communicate(timeout=5)
                if proc.returncode == 0:
                    self.cli.check_login()
                    return json.dumps({"success": True, "data": {"account": self.cli._account_name or ""}})
                else:
                    return json.dumps({"success": False, "error": stderr or stdout or "Login failed"})
            except subprocess.TimeoutExpired:
                self._login_proc = proc
                QTimer.singleShot(1000, self._poll_login)
                return json.dumps({"success": True, "data": {"account": "", "waiting": True}})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def _poll_login(self):
        proc = getattr(self, '_login_proc', None)
        if proc is None:
            return
        ret = proc.poll()
        if ret is not None:
            self._login_proc = None
            if ret == 0:
                self.cli.check_login()
        else:
            QTimer.singleShot(2000, self._poll_login)

    @Slot(result=str)
    def list_workers(self) -> str:
        call_id = "workers"
        self._run_worker(call_id, self.cli.list_workers)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(result=str)
    def list_pages(self) -> str:
        call_id = "pages"
        self._run_worker(call_id, self.cli.list_pages_projects)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(result=str)
    def list_kv(self) -> str:
        call_id = "kv"
        self._run_worker(call_id, self.cli.list_kv_namespaces)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(result=str)
    def list_r2(self) -> str:
        call_id = "r2"
        self._run_worker(call_id, self.cli.list_r2_buckets)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(result=str)
    def list_d1(self) -> str:
        call_id = "d1"
        self._run_worker(call_id, self.cli.list_d1_databases)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(result=str)
    def list_secrets(self) -> str:
        call_id = "secrets"
        self._run_worker(call_id, self.cli.list_secrets)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(str, result=str)
    def security_scan(self, project_path: str = ".") -> str:
        call_id = "scan"
        self._run_worker(call_id, self.cli.scan_local_config, project_path)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(str, result=str)
    def scan_secrets(self, directory: str) -> str:
        call_id = "secretscan"
        self._run_worker(call_id, self.cli.scan_directory_secrets, directory)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(result=str)
    def load_cache(self) -> str:
        return json.dumps(self._load_cache())

    @Slot(str, result=str)
    def save_cache(self, data_json: str) -> str:
        try:
            self._save_cache(json.loads(data_json))
            return json.dumps({"success": True})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @Slot(str, result=str)
    def save_local_path(self, project_name: str) -> str:
        """Browse and save a local directory path for a project."""
        try:
            d = QFileDialog.getExistingDirectory(self._main_window, "Select Local Project Directory")
            if d:
                self.cli._project_local_paths[project_name] = d
                self._config.setdefault("local_paths", {})[project_name] = d
                self._save_config()
                return json.dumps({"success": True, "path": d})
            return json.dumps({"success": False, "error": "No directory selected"})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @Slot(str, result=str)
    def get_local_path(self, project_name: str) -> str:
        """Get saved local directory path for a project."""
        p = self.cli._project_local_paths.get(project_name, "")
        if not p:
            p = self._config.get("local_paths", {}).get(project_name, "")
            if p:
                self.cli._project_local_paths[project_name] = p
        return json.dumps({"success": True, "path": p})

    @Slot(result=str)
    def get_all_local_paths(self) -> str:
        """Get all saved local directory paths."""
        paths = self._config.get("local_paths", {})
        return json.dumps({"success": True, "data": paths})

    @Slot(str, result=str)
    def load_settings(self, key: str) -> str:
        """Load a setting from config."""
        val = self._config.get("settings", {}).get(key, "")
        return json.dumps({"success": True, "value": val})

    @Slot(str, str, result=str)
    def save_setting(self, key: str, value: str) -> str:
        """Save a setting to config."""
        self._config.setdefault("settings", {})[key] = value
        self._save_config()
        return json.dumps({"success": True})

    @Slot(str, str, result=str)
    def ai_generate_fix(self, finding_json: str, project_path: str) -> str:
        try:
            finding = json.loads(finding_json)
            if not self.ollama or not self.ollama.is_available():
                return json.dumps({"success": False, "error": "Ollama not available"})
            result = self.cli.ai_generate_fix(finding, self.ollama)
            return json.dumps(result)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @Slot(str, result=str)
    def scan_dependencies(self, directory: str) -> str:
        call_id = "depscan"
        self._run_worker(call_id, self.cli.scan_dependencies, directory)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(str, result=str)
    def scan_env_exposure(self, directory: str) -> str:
        call_id = "envscan"
        self._run_worker(call_id, self.cli.scan_env_exposure, directory)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(str, result=str)
    def scan_security_headers(self, directory: str) -> str:
        call_id = "headerscan"
        self._run_worker(call_id, self.cli.scan_security_headers, directory)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(str, result=str)
    def scan_cors(self, directory: str) -> str:
        call_id = "corsscan"
        self._run_worker(call_id, self.cli.scan_cors, directory)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(str, result=str)
    def full_security_audit(self, directory: str) -> str:
        call_id = "fullaudit"
        def _audit():
            result = self.cli.full_security_audit(directory, self.ollama)
            # Save scan results to history
            if result.get("success"):
                self.warning_mgr.save_scan_result(
                    directory,
                    result.get("findings", []),
                    result.get("summary", {})
                )
            return result
        self._run_worker(call_id, _audit)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(result=str)
    def get_warning_history(self) -> str:
        call_id = "history"
        self._run_worker(call_id, self.warning_mgr.get_warning_history)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(result=str)
    def get_scan_history(self) -> str:
        return json.dumps({"success": True, "data": self.warning_mgr.get_scan_history()})

    @Slot(result=str)
    def get_always_ignored(self) -> str:
        call_id = "ignored"
        self._run_worker(call_id, self.warning_mgr.get_always_ignored)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(result=str)
    def ollama_status(self) -> str:
        call_id = "ollama_status"
        def _check():
            try:
                req = urllib.request.Request(f"{self.ollama.base_url}/api/tags", method="GET")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read())
                    models = [m.get("name", "") for m in data.get("models", [])]
                    if models and not self.ollama._model:
                        self.ollama._model = models[0]
                    self.ollama._available = True
                    return {"success": True, "data": {
                        "available": True,
                        "model": self.ollama._model or (models[0] if models else "none"),
                        "models": models
                    }}
            except Exception:
                self.ollama._available = False
                return {"success": True, "data": {"available": False, "model": "none", "models": []}}
        self._run_worker(call_id, _check)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(result=str)
    def ollama_models(self) -> str:
        call_id = "ollama_models"
        def _fetch():
            try:
                req = urllib.request.Request(f"{self.ollama.base_url}/api/tags", method="GET")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read())
                    models = [m.get("name", "") for m in data.get("models", [])]
                    return {"success": True, "data": models}
            except Exception:
                return {"success": True, "data": []}
        self._run_worker(call_id, _fetch)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(str, result=str)
    def ollama_set_model(self, model: str) -> str:
        self.ollama._model = model
        self.ollama._available = True
        self._config.setdefault("settings", {})["ollama_model"] = model
        self._save_config()
        return json.dumps({"success": True})

    @Slot(str, result=str)
    def ollama_set_url(self, url: str) -> str:
        self.ollama.base_url = url.rstrip("/")
        self.ollama._available = None
        self.ollama._model = None
        self._config.setdefault("settings", {})["ollama_url"] = url.rstrip("/")
        self._save_config()
        return self.ollama_status()

    @Slot(str, result=str)
    def ask_ai(self, question: str) -> str:
        call_id = "ask_ai"
        def _ask():
            if not self.ollama.is_available():
                return {"success": False, "error": "Ollama not connected. Start Ollama and load a model."}
            warnings_data = self.warning_mgr.get_warning_history()
            warnings = warnings_data.get("shown", []) if isinstance(warnings_data, dict) else []
            pages = self.cli.list_pages_projects()
            d1 = self.cli.list_d1_databases()
            kv = self.cli.list_kv_namespaces()
            r2 = self.cli.list_r2_buckets()
            workers = self.cli.list_workers()
            audience = self.warning_mgr.get_audience()
            response = self.ollama.ask_ai(
                question,
                warnings=warnings,
                deployments=pages,
                services={"d1": d1, "r2": r2, "kv": kv, "pages": pages, "workers": workers},
                audience=audience
            )
            return {"success": True, "data": {"response": response}}
        self._run_worker(call_id, _ask)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(str, str, result=str)
    def deploy(self, deploy_type: str, target: str) -> str:
        if deploy_type == "worker":
            result = self.cli.deploy_worker()
        elif deploy_type == "pages":
            result = self.cli.deploy_pages(target or "", ".")
        else:
            result = {"success": False, "error": f"Unknown type: {deploy_type}"}
        return json.dumps(result)

    @Slot(str, str, str, result=str)
    def smart_deploy(self, project_path: str, project_name: str = "", project_type: str = "") -> str:
        result = self.cli.smart_deploy(project_path, project_name, project_type)
        return json.dumps(result)

    @Slot(str, result=str)
    def get_project_details(self, name: str) -> str:
        details = self.cli.get_pages_project_details(name)
        return json.dumps({"success": True, "data": details})

    @Slot(str, result=str)
    def get_worker_details(self, name: str) -> str:
        details = self.cli.get_worker_details(name)
        return json.dumps({"success": True, "data": details})

    @Slot(str, result=str)
    def get_d1_details(self, name: str) -> str:
        details = self.cli.get_d1_details(name)
        return json.dumps({"success": True, "data": details})

    @Slot(str, str, result=str)
    def d1_execute(self, database: str, sql: str) -> str:
        call_id = "d1exec"
        self._run_worker(call_id, self.cli.d1_execute, database, sql)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(str, str, result=str)
    def d1_execute_file(self, database: str, file_path: str) -> str:
        call_id = "d1file"
        self._run_worker(call_id, self.cli.d1_execute_file, database, file_path)
        return json.dumps({"success": True, "call_id": call_id})

    @Slot(str, result=str)
    def get_kv_details(self, namespace_id: str) -> str:
        details = self.cli.get_kv_details(namespace_id)
        return json.dumps({"success": True, "data": details})

    @Slot(str, result=str)
    def get_r2_details(self, bucket: str) -> str:
        details = self.cli.get_r2_details(bucket)
        return json.dumps({"success": True, "data": details})

    @Slot(str, result=str)
    def create_d1_database(self, name: str) -> str:
        result = self.cli.create_d1_database(name)
        return json.dumps(result)

    @Slot(str, str, result=str)
    def create_r2_bucket(self, name: str, location: str = "auto") -> str:
        result = self.cli.create_r2_bucket(name, location)
        return json.dumps(result)

    @Slot(str, str, str, result=str)
    def upload_r2_file(self, bucket: str, key: str, file_path: str) -> str:
        result = self.cli.upload_r2_file(bucket, key, file_path)
        return json.dumps(result)

    @Slot(str, result=str)
    def list_r2_objects(self, bucket: str) -> str:
        objects = self.cli.list_r2_objects(bucket)
        return json.dumps({"success": True, "data": objects})

    @Slot(str, str, result=str)
    def delete_r2_object(self, bucket: str, key: str) -> str:
        result = self.cli.delete_r2_object(bucket, key)
        return json.dumps(result)

    @Slot(str, result=str)
    def delete_d1_database(self, name: str) -> str:
        result = self.cli.delete_d1_database(name)
        return json.dumps(result)

    @Slot(str, result=str)
    def delete_r2_bucket(self, name: str) -> str:
        result = self.cli.delete_r2_bucket(name)
        return json.dumps(result)

    @Slot(str, result=str)
    def create_worker_project(self, name: str) -> str:
        result = self.cli.create_worker_project(name)
        return json.dumps(result)

    @Slot(str, result=str)
    def create_pages_project(self, name: str) -> str:
        result = self.cli.create_pages_project(name)
        return json.dumps(result)

    @Slot(str, result=str)
    def delete_pages_project(self, name: str) -> str:
        result = self.cli.delete_pages_project(name)
        return json.dumps(result)

    @Slot(str, result=str)
    def delete_worker(self, name: str) -> str:
        result = self.cli.delete_worker(name)
        return json.dumps(result)

    @Slot(str, result=str)
    def get_worker_routes(self, name: str) -> str:
        routes = self.cli.get_worker_routes(name)
        return json.dumps({"success": True, "data": routes})

    @Slot(str, result=str)
    def redeploy_pages(self, name: str) -> str:
        result = self.cli.redeploy_pages(name)
        return json.dumps(result)

    @Slot(str, result=str)
    def redeploy_worker(self, name: str) -> str:
        local_path = self.cli._project_local_paths.get(name, "") or self._config.get("local_paths", {}).get(name, "")
        result = self.cli.redeploy_worker(name, local_path)
        return json.dumps(result)

    @Slot(result=str)
    def browse_file(self) -> str:
        try:
            file_path, _ = QFileDialog.getOpenFileName(None, "Select File to Upload", "", "All Files (*)")
            if file_path:
                return json.dumps({"success": True, "path": file_path})
            return json.dumps({"success": False, "error": "No file selected"})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @Slot(result=str)
    def browse_directory(self) -> str:
        try:
            dir_path = QFileDialog.getExistingDirectory(self._main_window, "Select Project Directory")
            if dir_path:
                return json.dumps({"success": True, "path": dir_path})
            return json.dumps({"success": False, "error": "No directory selected"})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @Slot(str, result=str)
    def validate_project_dir(self, dir_path: str) -> str:
        """Validate a local directory for Pages/Worker deployment."""
        p = Path(dir_path)
        if not p.exists():
            return json.dumps({"valid": False, "message": "Directory does not exist"})
        has_wrangler = any((p / f).exists() for f in ["wrangler.toml", "wrangler.jsonc", "wrangler.json"])
        has_pkg = (p / "package.json").exists()
        has_index = any((p / f).exists() for f in ["index.html", "index.js", "index.ts", "src/index.ts", "src/index.js", "src/index.tsx", "src/index.jsx"])
        has_worker = any((p / f).exists() for f in ["worker.js", "worker.ts", "src/worker.js", "src/worker.ts"])

        if has_wrangler:
            # Worker project
            return json.dumps({"valid": True, "message": "Worker project detected (wrangler.toml found)", "type": "worker"})
        elif has_worker:
            return json.dumps({"valid": True, "message": "Worker source detected (worker.js/ts found)", "type": "worker"})
        elif has_pkg and has_index:
            return json.dumps({"valid": True, "message": "Frontend project detected (package.json + index found)", "type": "pages"})
        elif has_pkg:
            return json.dumps({"valid": True, "message": "Node project detected (package.json found) — will build then deploy", "type": "pages"})
        elif has_index:
            return json.dumps({"valid": True, "message": "Static site detected (index.html found)", "type": "pages"})
        else:
            return json.dumps({"valid": False, "message": "No recognizable project files. Add wrangler.toml, package.json, or index.html"})

    @Slot(str, str, result=str)
    def fix_finding(self, finding_json: str, project_path: str = ".") -> str:
        try:
            finding = json.loads(finding_json)
        except json.JSONDecodeError:
            return json.dumps({"success": False, "error": "Invalid finding data"})
        result = self.cli.fix_finding(finding, project_path)
        if result.get("success"):
            self.warning_mgr.fix_warning(finding.get("id", ""), result)
        return json.dumps(result)

    @Slot(str, result=str)
    def ignore_warning(self, warning_id: str) -> str:
        self.warning_mgr.ignore_warning(warning_id)
        return json.dumps({"success": True})

    @Slot(str, result=str)
    def ignore_check_always(self, check_id: str) -> str:
        self.warning_mgr.ignore_check_always(check_id)
        return json.dumps({"success": True})

    @Slot(str, result=str)
    def unignore_check(self, check_id: str) -> str:
        self.warning_mgr.unignore_check(check_id)
        return json.dumps({"success": True})

    @Slot(str, result=str)
    def set_audience(self, audience: str) -> str:
        self.warning_mgr.set_audience(audience)
        return json.dumps({"success": True})

    @Slot(result=str)
    def get_audience(self) -> str:
        return json.dumps({"success": True, "data": self.warning_mgr.get_audience()})

    @Slot(str, result=str)
    def explain_term(self, term: str) -> str:
        audience = self.warning_mgr.get_audience()
        if self.ollama.is_available():
            explanation = self.ollama.explain_term(term, audience)
        else:
            explanation = explain_term(term, audience)
        return json.dumps({"success": True, "data": {"term": term, "explanation": explanation}})

    @Slot(str, result=str)
    def analyze_finding(self, finding_json: str) -> str:
        if not self.ollama.is_available():
            return json.dumps({"success": False, "error": "Ollama not connected"})
        try:
            finding = json.loads(finding_json)
        except json.JSONDecodeError:
            return json.dumps({"success": False, "error": "Invalid finding data"})
        file_path = finding.get("file", "")
        file_content = ""
        if file_path and Path(file_path).exists():
            try:
                file_content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass
        result = self.ollama.analyze_finding(finding, file_content)
        return json.dumps({"success": True, "data": result})

    @Slot(str, result=str)
    def explain_finding(self, finding_json: str) -> str:
        try:
            finding = json.loads(finding_json)
        except json.JSONDecodeError:
            return json.dumps({"success": False, "error": "Invalid finding data"})
        audience = self.warning_mgr.get_audience()
        if self.ollama.is_available():
            explanation = self.ollama.explain_finding(finding, audience)
        else:
            explanation = finding.get("simple_explanation", finding.get("message", ""))
        return json.dumps({"success": True, "data": {"explanation": explanation}})


class MainWindow(QWebEngineView):
    def __init__(self, bridge: Bridge):
        super().__init__()
        self.bridge = bridge
        bridge.set_main_window(self)
        self.setWindowTitle("Nimbus")
        self.resize(1280, 800)

        self._channel = QWebChannel()
        self._channel.registerObject("pybridge", self.bridge)
        self.page().setWebChannel(self._channel)

        self.setHtml(self._load_html(), QUrl.fromLocalFile(str(INDEX_HTML)))
        self.show()

    def _load_html(self) -> str:
        html = INDEX_HTML.read_text(encoding="utf-8")
        inject = """
        <script>
            if (!window._pybridgeReady) {
                window._pybridgeReady = true;
                var s = document.createElement('script');
                s.src = 'qrc:///qtwebchannel/qwebchannel.js';
                s.onload = function() {
                    new QWebChannel(qt.webChannelTransport, function(ch) {
                        window.pybridge = ch.objects.pybridge;
                        if (window.API) window.API._bridge = window.pybridge;
                        if (typeof window._onBridgeReady === 'function') window._onBridgeReady();
                    });
                };
                document.head.appendChild(s);
            }
        </script>
        """
        if "</body>" in html:
            html = html.replace("</body>", inject + "</body>")
        else:
            html += inject
        return html


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet("QWebEngineView { background: #0e2137; border: none; }")

    cli = WranglerCLI()
    warning_mgr = WarningManager()
    ollama = OllamaClient()
    monitor = SecurityMonitor(cli, warning_mgr)

    bridge = Bridge(cli, monitor, warning_mgr, ollama)
    window = MainWindow(bridge)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
