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


class Bridge(QObject):
    """Python bridge — all methods run in Qt event loop.
    Heavy operations use QTimer.singleShot to avoid blocking."""

    def __init__(self, cli: WranglerCLI, monitor: SecurityMonitor,
                 warning_mgr: WarningManager, ollama: OllamaClient, parent=None):
        super().__init__(parent)
        self.cli = cli
        self.monitor = monitor
        self.warning_mgr = warning_mgr
        self.ollama = ollama
        self._js_queue: list[str] = []

    def _eval_js(self, js: str):
        """Queue JS to be evaluated on the page."""
        self._js_queue.append(js)

    @Slot(result=str)
    def check_login(self) -> str:
        try:
            logged_in = self.cli.check_login()
            return json.dumps({"success": True, "data": {
                "logged_in": logged_in,
                "account": self.cli._account_name or ""
            }})
        except Exception as e:
            return json.dumps({"success": True, "data": {"logged_in": False, "account": ""}})

    @Slot(result=str)
    def login(self) -> str:
        """Run wrangler login in a subprocess. Returns immediately."""
        try:
            proc = subprocess.Popen(
                "wrangler login", shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                encoding="utf-8", errors="replace"
            )
            # Don't wait — let the browser OAuth flow happen
            # Poll briefly for immediate failures (command not found, etc.)
            try:
                stdout, stderr = proc.communicate(timeout=5)
                # If we got here quickly, login either succeeded or failed
                if proc.returncode == 0:
                    self.cli.check_login()
                    return json.dumps({"success": True, "data": {"account": self.cli._account_name or ""}})
                else:
                    return json.dumps({"success": False, "error": stderr or stdout or "Login failed"})
            except subprocess.TimeoutExpired:
                # Still running — browser is open, that's expected
                # Start a background timer to check when it completes
                self._login_proc = proc
                QTimer.singleShot(1000, self._poll_login)
                return json.dumps({"success": True, "data": {"account": "", "waiting": True}})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def _poll_login(self):
        """Poll the login process in background."""
        proc = getattr(self, '_login_proc', None)
        if proc is None:
            return
        ret = proc.poll()
        if ret is not None:
            # Process finished
            self._login_proc = None
            if ret == 0:
                self.cli.check_login()
        else:
            # Still running, check again in 2s
            QTimer.singleShot(2000, self._poll_login)

    @Slot(result=str)
    def list_workers(self) -> str:
        return json.dumps({"success": True, "data": self.cli.list_workers_from_pages()})

    @Slot(result=str)
    def list_pages(self) -> str:
        return json.dumps({"success": True, "data": self.cli.list_pages_projects()})

    @Slot(result=str)
    def list_kv(self) -> str:
        return json.dumps({"success": True, "data": self.cli.list_kv_namespaces()})

    @Slot(result=str)
    def list_r2(self) -> str:
        return json.dumps({"success": True, "data": self.cli.list_r2_buckets()})

    @Slot(result=str)
    def list_d1(self) -> str:
        return json.dumps({"success": True, "data": self.cli.list_d1_databases()})

    @Slot(result=str)
    def list_secrets(self) -> str:
        return json.dumps({"success": True, "data": self.cli.list_secrets()})

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

    @Slot(result=str)
    def list_workers(self) -> str:
        workers = self.cli.list_workers()
        return json.dumps({"success": True, "data": workers})

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

    @Slot(result=str)
    def browse_file(self) -> str:
        """Open a native file dialog and return the selected path."""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                None, "Select File to Upload", "",
                "All Files (*)"
            )
            if file_path:
                return json.dumps({"success": True, "path": file_path})
            return json.dumps({"success": False, "error": "No file selected"})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @Slot(result=str)
    def browse_directory(self) -> str:
        """Open a native directory dialog and return the selected path."""
        try:
            dir_path = QFileDialog.getExistingDirectory(
                None, "Select Project Directory", ""
            )
            if dir_path:
                return json.dumps({"success": True, "path": dir_path})
            return json.dumps({"success": False, "error": "No directory selected"})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @Slot(str, result=str)
    def security_scan(self, project_path: str = "") -> str:
        findings = self.cli.scan_local_config(project_path or ".")
        active = self.warning_mgr.process_findings(findings)
        return json.dumps({"success": True, "data": active})

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

    @Slot(result=str)
    def get_warning_history(self) -> str:
        return json.dumps({"success": True, "data": self.warning_mgr.get_warning_history()})

    @Slot(result=str)
    def get_always_ignored(self) -> str:
        return json.dumps({"success": True, "data": self.warning_mgr.get_always_ignored()})

    @Slot(result=str)
    def get_glossary(self) -> str:
        return json.dumps({"success": True, "data": GLOSSARY})

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

    @Slot(str, result=str)
    def set_audience(self, audience: str) -> str:
        self.warning_mgr.set_audience(audience)
        return json.dumps({"success": True})

    @Slot(result=str)
    def get_audience(self) -> str:
        return json.dumps({"success": True, "data": self.warning_mgr.get_audience()})

    @Slot(result=str)
    def ollama_status(self) -> str:
        """Fast check — just see if Ollama is reachable."""
        try:
            req = urllib.request.Request(f"{self.ollama.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read())
                models = [m.get("name", "") for m in data.get("models", [])]
                if models and not self.ollama._model:
                    self.ollama._model = models[0]
                self.ollama._available = True
                return json.dumps({"success": True, "data": {
                    "available": True,
                    "model": self.ollama._model or models[0] if models else "none",
                    "models": models
                }})
        except Exception:
            self.ollama._available = False
            return json.dumps({"success": True, "data": {"available": False, "model": "none", "models": []}})

    @Slot(result=str)
    def ollama_models(self) -> str:
        """Fetch available Ollama models."""
        try:
            req = urllib.request.Request(f"{self.ollama.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
                models = [m.get("name", "") for m in data.get("models", [])]
                return json.dumps({"success": True, "data": models})
        except Exception:
            return json.dumps({"success": True, "data": []})

    @Slot(str, result=str)
    def ollama_set_model(self, model: str) -> str:
        self.ollama._model = model
        self.ollama._available = True
        return json.dumps({"success": True})

    @Slot(str, result=str)
    def ollama_set_url(self, url: str) -> str:
        self.ollama.base_url = url.rstrip("/")
        self.ollama._available = None
        self.ollama._model = None
        return self.ollama_status()


class MainWindow(QWebEngineView):
    def __init__(self, bridge: Bridge):
        super().__init__()
        self.bridge = bridge
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
    app.setStyleSheet("QWebEngineView { background: #0b1a2e; border: none; }")

    cli = WranglerCLI()
    warning_mgr = WarningManager()
    ollama = OllamaClient()
    monitor = SecurityMonitor(cli, warning_mgr)

    bridge = Bridge(cli, monitor, warning_mgr, ollama)
    window = MainWindow(bridge)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
