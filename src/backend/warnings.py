"""Warning management system with history, preferences, and Ollama-powered smart analysis."""

import json
import time
from pathlib import Path
from typing import Optional, Callable


DATA_DIR = Path.home() / ".cloudguard"
WARNINGS_FILE = DATA_DIR / "warnings.json"
PREFS_FILE = DATA_DIR / "preferences.json"
SCAN_HISTORY_FILE = DATA_DIR / "scan_history.json"


def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load_json(path: Path, default=None):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return default if default is not None else {}


def _save_json(path: Path, data):
    _ensure_data_dir()
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# ── Glossary: explains every technical term ────────────────

GLOSSARY = {
    "SSL": {
        "term": "SSL/TLS",
        "simple": "The technology that encrypts data between your website and visitors. Like sealing a letter in an envelope instead of sending a postcard.",
        "technical": "Secure Sockets Layer / Transport Layer Security — cryptographic protocols for authenticated data transport.",
        "why_it_matters": "Without SSL, anyone on the same network can read passwords, credit cards, and messages sent to your site."
    },
    "Full Strict": {
        "term": "SSL Mode: Full (Strict)",
        "simple": "The strongest encryption setting. Your server proves it's really yours using a valid certificate.",
        "technical": "End-to-end TLS with origin certificate validation. Prevents man-in-the-middle attacks on the Cloudflare-to-origin connection.",
        "why_it_matters": "Lower modes like 'Flexible' send data unencrypted between Cloudflare and your server."
    },
    "WAF": {
        "term": "Web Application Firewall (WAF)",
        "simple": "A security guard for your website that blocks hackers, bots, and attacks before they reach your site.",
        "technical": "Layer 7 proxy that inspects HTTP traffic against rule sets (managed + custom) to block malicious requests.",
        "why_it_matters": "Without a WAF, your site is exposed to SQL injection, XSS, and other web attacks."
    },
    "HSTS": {
        "term": "HTTP Strict Transport Security (HSTS)",
        "simple": "Tells browsers to always use the secure (HTTPS) version of your site, even if someone types http://.",
        "technical": "Response header that instructs browsers to only connect via HTTPS for a specified duration, including subdomains.",
        "why_it_matters": "Prevents downgrade attacks where attackers force users to the unencrypted version."
    },
    "DNSSEC": {
        "term": "DNS Security Extensions (DNSSEC)",
        "simple": "A digital signature system for the internet's address book. Prevents hackers from redirecting your domain to fake servers.",
        "technical": "Cryptographic signing of DNS records to prevent cache poisoning and spoofing attacks.",
        "why_it_matters": "Without DNSSEC, attackers can hijack DNS responses and redirect your visitors to malicious sites."
    },
    "Rate Limiting": {
        "term": "Rate Limiting",
        "simple": "Speed limits for your website. Prevents anyone from flooding your site with too many requests (like a DDoS attack).",
        "technical": "Throttling mechanism that limits requests per second/minute from a single IP or for a specific endpoint.",
        "why_it_matters": "Without rate limiting, attackers can crash your site or brute-force login pages."
    },
    "CORS": {
        "term": "Cross-Origin Resource Sharing (CORS)",
        "simple": "Rules that control which other websites can access your API. Like deciding who gets a key to your building.",
        "technical": "Browser security mechanism using HTTP headers to control which origins can read responses from your API.",
        "why_it_matters": "Misconfigured CORS lets any website steal data from your API on behalf of logged-in users."
    },
    "CSP": {
        "term": "Content Security Policy (CSP)",
        "simple": "A whitelist of allowed content sources. Blocks hackers from injecting malicious scripts into your pages.",
        "technical": "HTTP header that restricts which scripts, styles, images, and other resources browsers are allowed to load.",
        "why_it_matters": "Without CSP, XSS attacks can inject arbitrary JavaScript that steals user data."
    },
    "Cloudflare Worker": {
        "term": "Cloudflare Worker",
        "simple": "A small program that runs on Cloudflare's servers worldwide. Like a security guard stationed in every city.",
        "technical": "Serverless compute function on Cloudflare's edge network, running V8 isolates with sub-millisecond cold starts.",
        "why_it_matters": "Workers can manipulate requests, add security headers, and block threats before they reach your origin."
    },
    "KV Namespace": {
        "term": "KV Namespace (Key-Value Store)",
        "simple": "A super-fast global dictionary. Store small pieces of data (like settings or session tokens) that can be read from anywhere instantly.",
        "technical": "Globally distributed eventually-consistent key-value store with ~50ms read latency at the edge.",
        "why_it_matters": "Used for caching, configuration, and session management without hitting your database."
    },
    "R2 Bucket": {
        "term": "R2 Bucket (Object Storage)",
        "simple": "Cloud storage for files — images, videos, backups, documents. Like a hard drive in the cloud.",
        "technical": "S3-compatible object storage with zero egress fees, suitable for static assets and large file storage.",
        "why_it_matters": "If your bucket is public, anyone can read (or potentially write to) your stored files."
    },
    "D1 Database": {
        "term": "D1 Database",
        "simple": "A SQL database that runs globally on Cloudflare. Store structured data like user accounts, products, or orders.",
        "technical": "Globally distributed SQLite-based relational database with point-in-time recovery.",
        "why_it_matters": "Your database contains your most sensitive data — credentials, PII, business logic."
    },
    "API Token": {
        "term": "API Token",
        "simple": "A password that lets programs talk to Cloudflare on your behalf. Like giving a valet key — limited access, not full control.",
        "technical": "Scoped OAuth token with specific permissions (read/write) for specific resources (zones, workers, etc.).",
        "why_it_matters": "Overly permissive tokens let attackers control your entire Cloudflare account if compromised."
    },
    "Origin IP": {
        "term": "Origin Server IP",
        "simple": "The real address of your server. If hackers find it, they can attack your server directly, bypassing Cloudflare's protection.",
        "technical": "The actual server IP behind Cloudflare's reverse proxy, potentially exposed via DNS history or email headers.",
        "why_it_matters": "Direct attacks bypass all Cloudflare security features (WAF, DDoS protection, etc.)."
    },
    "Canary File": {
        "term": "Canary / Honeypot File",
        "simple": "A trap file placed among your real files. If anyone touches it, you know something is wrong.",
        "technical": "Decoy file monitored for access — any read/write triggers an immediate alert, indicating unauthorized activity.",
        "why_it_matters": "Early detection of ransomware or data breaches before significant damage occurs."
    },
    "Entropy": {
        "term": "Entropy (in security context)",
        "simple": "A measure of randomness. Encrypted data looks very random (high entropy). Normal text is predictable (low entropy).",
        "technical": "Shannon entropy measured in bits/byte. Plaintext: ~3-5 bits. Encrypted: ~7.5-8.0 bits.",
        "why_it_matters": "Sudden entropy spikes in files indicate encryption — a hallmark of ransomware attacks."
    }
}


def get_glossary(term: str = None) -> dict:
    if term:
        return GLOSSARY.get(term, {"error": f"Term '{term}' not found in glossary."})
    return GLOSSARY


def explain_term(term: str, audience: str = "beginner") -> str:
    entry = GLOSSARY.get(term)
    if not entry:
        return f"No explanation available for '{term}'."
    if audience == "technical":
        return entry.get("technical", entry["simple"])
    return entry["simple"]


# ── Warning System ─────────────────────────────────────────

class WarningManager:
    """Manages security warnings with history, preferences, and smart analysis."""

    def __init__(self):
        self._listeners: list[Callable] = []
        self._warnings: dict = _load_json(WARNINGS_FILE, {"shown": {}, "ignored": {}, "fixed": {}})
        self._prefs: dict = _load_json(PREFS_FILE, {"always_ignore_checks": [], "audience": "beginner"})
        self._scan_history: list = _load_json(SCAN_HISTORY_FILE, [])

    def on_event(self, callback: Callable):
        self._listeners.append(callback)

    def _emit(self, event: str, data: dict):
        for cb in self._listeners:
            try:
                cb(event, data)
            except Exception:
                pass

    def _save(self):
        _save_json(WARNINGS_FILE, self._warnings)
        _save_json(PREFS_FILE, self._prefs)
        _save_json(SCAN_HISTORY_FILE, self._scan_history)

    def get_audience(self) -> str:
        return self._prefs.get("audience", "beginner")

    def set_audience(self, audience: str):
        self._prefs["audience"] = audience
        self._save()

    def should_ignore_check(self, check_id: str) -> bool:
        return check_id in self._prefs.get("always_ignore_checks", [])

    def ignore_check_always(self, check_id: str):
        prefs = self._prefs.setdefault("always_ignore_checks", [])
        if check_id not in prefs:
            prefs.append(check_id)
            self._save()
            self._emit("preference_changed", {"check": check_id, "action": "always_ignore"})

    def unignore_check(self, check_id: str):
        prefs = self._prefs.get("always_ignore_checks", [])
        if check_id in prefs:
            prefs.remove(check_id)
            self._save()
            self._emit("preference_changed", {"check": check_id, "action": "unignore"})

    def record_shown(self, warning_id: str, finding: dict):
        self._warnings["shown"][warning_id] = {
            **finding,
            "id": warning_id,
            "shown_at": time.time(),
            "shown_count": self._warnings["shown"].get(warning_id, {}).get("shown_count", 0) + 1
        }
        self._save()

    def ignore_warning(self, warning_id: str, reason: str = ""):
        if warning_id in self._warnings["shown"]:
            entry = self._warnings["shown"].pop(warning_id)
            entry["ignored_at"] = time.time()
            entry["ignore_reason"] = reason
            self._warnings["ignored"][warning_id] = entry
            self._save()
            self._emit("warning_ignored", {"id": warning_id, "finding": entry})

    def fix_warning(self, warning_id: str, result: dict):
        if warning_id in self._warnings["shown"]:
            entry = self._warnings["shown"].pop(warning_id)
            entry["fixed_at"] = time.time()
            entry["fix_result"] = result
            self._warnings["fixed"][warning_id] = entry
            self._save()
            self._emit("warning_fixed", {"id": warning_id, "finding": entry})

    def get_active_warnings(self) -> list[dict]:
        return list(self._warnings["shown"].values())

    def get_warning_history(self) -> dict:
        return {
            "shown": list(self._warnings["shown"].values()),
            "ignored": list(self._warnings["ignored"].values()),
            "fixed": list(self._warnings["fixed"].values()),
            "stats": {
                "total_shown": len(self._warnings["shown"]),
                "total_ignored": len(self._warnings["ignored"]),
                "total_fixed": len(self._warnings["fixed"])
            }
        }

    def get_always_ignored(self) -> list[str]:
        return self._prefs.get("always_ignore_checks", [])

    def save_scan_result(self, directory: str, findings: list[dict], summary: dict):
        """Save a scan result to history."""
        import time
        entry = {
            "id": f"scan_{int(time.time() * 1000)}",
            "directory": directory,
            "timestamp": time.time(),
            "findings_count": len(findings),
            "summary": summary,
            "findings": findings[:50]  # Cap at 50 to avoid huge files
        }
        self._scan_history.insert(0, entry)
        # Keep only last 50 scans
        if len(self._scan_history) > 50:
            self._scan_history = self._scan_history[:50]
        self._save()

    def get_scan_history(self) -> list[dict]:
        """Get all saved scan results."""
        return self._scan_history

    def process_findings(self, findings: list[dict]) -> list[dict]:
        """Filter findings based on user preferences and history."""
        always_ignore = set(self._prefs.get("always_ignore_checks", []))
        active = []
        for f in findings:
            check = f.get("check", "")
            wid = f.get("id", f"{check}_{f.get('file', '')}")
            f["id"] = wid
            if check in always_ignore:
                continue
            if wid in self._warnings.get("ignored", {}):
                continue
            if wid in self._warnings.get("fixed", {}):
                continue
            self.record_shown(wid, f)
            active.append(f)
        return active


# ── Ollama Integration ────────────────────────────────────

class OllamaClient:
    """Lightweight Ollama client for codebase analysis and explanations."""

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self._available: Optional[bool] = None
        self._model: Optional[str] = None

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            import urllib.request
            req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
                models = data.get("models", [])
                if models:
                    self._model = models[0].get("name", "")
                    self._available = True
                else:
                    self._available = False
        except Exception:
            self._available = False
        return self._available

    def get_model(self) -> str:
        if not self._model:
            self.is_available()
        return self._model or "none"

    def _chat(self, prompt: str, context: str = "") -> str:
        if not self.is_available():
            return ""
        try:
            import urllib.request
            messages = []
            if context:
                messages.append({"role": "system", "content": context})
            messages.append({"role": "user", "content": prompt})

            payload = json.dumps({
                "model": self._model,
                "messages": messages,
                "stream": False
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{self.base_url}/api/chat",
                data=payload,
                method="POST",
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                return data.get("message", {}).get("content", "")
        except Exception:
            return ""

    def analyze_finding(self, finding: dict, file_content: str = "") -> dict:
        """Use Ollama to analyze whether a finding is a real issue."""
        check = finding.get("check", "")
        file_path = finding.get("file", "")
        message = finding.get("message", "")

        context = (
            "You are a Cloudflare security expert helping a non-technical user understand "
            "a security finding. Be clear, concise, and practical. "
            "Reply in JSON format with these fields: "
            '{"is_real_issue": true/false, "explanation": "simple explanation", '
            '"recommendation": "what to do", "technical_details": "for advanced users", '
            '"data_at_risk": "what data could be affected", "severity_justification": "why this severity"}'
        )

        prompt = f"Security finding: {message}\nFile: {file_path}\nCheck type: {check}"
        if file_content:
            prompt += f"\n\nFile content:\n```\n{file_content[:2000]}\n```"

        response = self._chat(prompt, context)
        if not response:
            return {"is_real_issue": True, "explanation": "Could not analyze with Ollama."}

        try:
            # Try to extract JSON from response
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            pass

        return {"is_real_issue": True, "explanation": response}

    def explain_finding(self, finding: dict, audience: str = "beginner") -> str:
        """Get a simple explanation of a finding."""
        check = finding.get("check", "")
        message = finding.get("message", "")

        context = f"You are a friendly security tutor. The user is a {audience}. Explain clearly and briefly."

        prompt = (
            f"Explain this security finding in simple terms:\n"
            f"Finding: {message}\nType: {check}\n\n"
            f"Include: 1) What it means 2) Why it matters 3) What to do about it"
        )

        response = self._chat(prompt, context)
        return response or f"This is a {check} security finding. {message}"

    def explain_term(self, term: str, audience: str = "beginner") -> str:
        """Use Ollama to explain a technical term."""
        context = f"You are a patient teacher explaining to a {audience}. Use analogies and simple language."
        prompt = f"Explain '{term}' in the context of web security and cloud deployment. Be concise."
        response = self._chat(prompt, context)
        return response or explain_term(term, audience)

    def ask_ai(self, question: str, warnings: list[dict] = None, deployments: list[dict] = None,
               services: dict = None, audience: str = "beginner") -> str:
        """Chat with AI that has full context of the user's Cloudflare setup."""
        context_parts = [
            f"You are Nimbus AI, a Cloudflare security assistant for a {audience} user.",
            "You have access to the user's Cloudflare account data. Answer questions about their",
            "security issues, deployments, services, and Cloudflare in general.",
            "Be helpful, clear, and practical. If the user asks about a specific issue, reference it.",
        ]

        if warnings:
            context_parts.append("\nActive security issues:")
            for w in warnings[:10]:
                severity = w.get("severity", "")
                message = w.get("message", "")
                check = w.get("check", "")
                context_parts.append(f"- [{severity}] {check}: {message}")

        if deployments:
            context_parts.append("\nRecent deployments:")
            for d in deployments[:10]:
                name = d.get("name", "")
                dtype = d.get("type", "")
                modified = d.get("modified", d.get("time", ""))
                context_parts.append(f"- {name} ({dtype}) - last modified: {modified}")

        if services:
            if services.get("d1"):
                context_parts.append(f"\nD1 databases: {len(services['d1'])} ({', '.join(d.get('name','') for d in services['d1'][:5])})")
            if services.get("r2"):
                context_parts.append(f"R2 buckets: {len(services['r2'])} ({', '.join(b.get('name','') for b in services['r2'][:5])})")
            if services.get("kv"):
                context_parts.append(f"KV namespaces: {len(services['kv'])}")
            if services.get("pages"):
                context_parts.append(f"Pages projects: {len(services['pages'])} ({', '.join(p.get('name','') for p in services['pages'][:5])})")
            if services.get("workers"):
                context_parts.append(f"Workers: {len(services['workers'])} ({', '.join(w.get('name','') for w in services['workers'][:5])})")

        context = "\n".join(context_parts)
        response = self._chat(question, context)
        return response or "I couldn't process that question. Make sure Ollama is running and a model is loaded."
