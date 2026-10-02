import asyncio
import html
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/config/config.yaml"))
USERNAME = os.environ.get("SIPHON_USERNAME", "siphon")
PASSWORD = os.environ.get("SIPHON_PASSWORD", "")
ICON_URL = os.environ.get("SIPHON_ICON_URL", "/icon.png")
ALLOWED_ROOTS = tuple(Path(p).resolve() for p in os.environ.get(
    "ALLOWED_DEST_ROOTS", "/html/www/html,/SERVERS"
).split(",") if p.strip())
RUN_ON_START = os.environ.get("RUN_ON_START", "false").lower() == "true"
DEFAULT_INTERVAL = 15
HANDLERS = {"download", "content_filter", "xml_event_filter"}
MAX_FILTER_BYTES = 8 * 1024 * 1024
RESERVED_CURL_FLAGS = {
    "-o", "--output", "-O", "--remote-name", "--remote-name-all",
    "-K", "--config", "-u", "--user", "-H", "--header", "-d", "--data",
    "--data-binary", "-F", "--form", "--upload-file", "-T", "--url",
}
WURM_FILTERS = [
    {"name": "Camp appearance", "field": "text", "match": "regex",
     "value": r"\bbattle camp\b.*\bhas appeared\b", "ignore_case": True},
    {"name": "Camp claim", "field": "text", "match": "regex",
     "value": r"\bhas claimed battle camp\b", "ignore_case": True},
    {"name": "Secure victory", "field": "text", "match": "contains",
     "value": "secure victory", "ignore_case": True},
]
security = HTTPBasic()
run_lock = asyncio.Lock()
state: dict[str, Any] = {"last_run": None, "running": False, "results": []}


def default_config() -> dict[str, Any]:
    return {"interval_minutes": DEFAULT_INTERVAL, "jobs": []}


def config_read() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_write(default_config())
    with CONFIG_PATH.open("r", encoding="utf-8") as stream:
        value = yaml.safe_load(stream) or default_config()
    migrated = False
    for job in value.get("jobs", []) if isinstance(value, dict) else []:
        if isinstance(job, dict) and job.get("handler") == "wurm_camps":
            job["handler"] = "xml_event_filter"
            job["options"] = {
                "record_tag": "message",
                "identity_fields": ["time", "text"],
                "filters": WURM_FILTERS,
            }
            migrated = True
    validate_config(value)
    if migrated:
        config_write(value)
    return value


def config_write(value: dict[str, Any]) -> None:
    validate_config(value)
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".config-", dir=CONFIG_PATH.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            yaml.safe_dump(value, stream, sort_keys=False, allow_unicode=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, CONFIG_PATH)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def validate_source(source: str) -> None:
    parsed = urllib.parse.urlsplit(source)
    if parsed.scheme not in {"http", "https", "file"}:
        raise ValueError("Source must use http, https, or file URL format.")
    if parsed.scheme == "file":
        local_path = Path(urllib.parse.unquote(parsed.path)).resolve()
        if not under_roots(local_path):
            raise ValueError("A file:// source must be under an allowed mounted root.")
    elif not parsed.hostname:
        raise ValueError("Source URL needs a hostname.")


def under_roots(path: Path) -> bool:
    return any(path == root or root in path.parents for root in ALLOWED_ROOTS)


def checked_destination(destination: str) -> Path:
    path = Path(destination)
    if not path.is_absolute():
        raise ValueError("Destination must be an absolute path inside a mounted destination root.")
    parent = path.parent.resolve()
    checked = parent / path.name
    if not under_roots(checked):
        raise ValueError("Destination is outside the configured allowed roots.")
    if path.exists() and path.is_dir():
        raise ValueError("Destination must include a filename.")
    if not parent.exists() or not parent.is_dir():
        raise ValueError("Destination directory does not exist in the container.")
    return checked


def validate_config(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("Configuration must be a YAML mapping.")
    interval = value.get("interval_minutes", DEFAULT_INTERVAL)
    if not isinstance(interval, int) or not 1 <= interval <= 1440:
        raise ValueError("interval_minutes must be an integer from 1 to 1440.")
    jobs = value.get("jobs", [])
    if not isinstance(jobs, list):
        raise ValueError("jobs must be a list.")
    seen: set[str] = set()
    for job in jobs:
        if not isinstance(job, dict):
            raise ValueError("Each job must be a mapping.")
        for key in ("id", "name", "source", "destination"):
            if not isinstance(job.get(key), str) or not job[key].strip():
                raise ValueError(f"Each job needs a non-empty {key}.")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", job["id"]):
            raise ValueError(f"Invalid job id: {job['id']}")
        if job["id"] in seen:
            raise ValueError(f"Job ids must be unique: {job['id']}")
        seen.add(job["id"])
        validate_source(job["source"])
        checked_destination(job["destination"])
        handler = job.get("handler", "download")
        if handler not in HANDLERS:
            raise ValueError(f"Unknown handler: {handler}")
        args = job.get("args", [])
        if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
            raise ValueError("args must be a list of strings.")
        if any(arg in RESERVED_CURL_FLAGS or arg.split("=", 1)[0] in RESERVED_CURL_FLAGS for arg in args):
            raise ValueError("args cannot override curl's source, output, headers, credentials, or body.")
        options = job.get("options", {})
        if not isinstance(options, dict):
            raise ValueError("options must be a mapping.")
        if handler == "xml_event_filter":
            record_tag = options.get("record_tag", "message")
            identity_fields = options.get("identity_fields", ["time", "text"])
            filters = options.get("filters", [])
            if not isinstance(record_tag, str) or not record_tag.strip():
                raise ValueError("XML filter record_tag must be a non-empty element name.")
            if not isinstance(identity_fields, list) or not identity_fields or any(not isinstance(x, str) or not x for x in identity_fields):
                raise ValueError("XML filter identity_fields must be a non-empty list of field names.")
            if not isinstance(filters, list):
                raise ValueError("XML filters must be a list.")
            filter_names: set[str] = set()
            for rule in filters:
                if not isinstance(rule, dict):
                    raise ValueError("Each XML filter must be a mapping.")
                for key in ("name", "field", "value", "match"):
                    if not isinstance(rule.get(key), str) or not rule[key].strip():
                        raise ValueError(f"Each XML filter needs a non-empty {key}.")
                if rule["name"] in filter_names:
                    raise ValueError("XML filter names must be unique within a job.")
                filter_names.add(rule["name"])
                if rule["match"] not in {"contains", "regex"}:
                    raise ValueError("XML filter match must be contains or regex.")
                if not isinstance(rule.get("ignore_case", True), bool):
                    raise ValueError("XML filter ignore_case must be true or false.")
                if rule["match"] == "regex":
                    try:
                        re.compile(rule["value"], re.IGNORECASE if rule.get("ignore_case", True) else 0)
                    except re.error as exc:
                        raise ValueError(f"Invalid regex in filter {rule['name']}: {exc}") from exc
        elif handler == "content_filter":
            filters = options.get("filters", [])
            if not isinstance(filters, list):
                raise ValueError("Content filters must be a list.")
            filter_names: set[str] = set()
            for rule in filters:
                if not isinstance(rule, dict):
                    raise ValueError("Each content filter must be a mapping.")
                for key in ("name", "value", "match"):
                    if not isinstance(rule.get(key), str) or not rule[key].strip():
                        raise ValueError(f"Each content filter needs a non-empty {key}.")
                if rule["name"] in filter_names:
                    raise ValueError("Content filter names must be unique within a job.")
                filter_names.add(rule["name"])
                if rule["match"] not in {"contains", "regex"}:
                    raise ValueError("Content filter match must be contains or regex.")
                if not isinstance(rule.get("ignore_case", True), bool):
                    raise ValueError("Content filter ignore_case must be true or false.")
                if rule["match"] == "regex":
                    try:
                        re.compile(rule["value"], re.IGNORECASE if rule.get("ignore_case", True) else 0)
                    except re.error as exc:
                        raise ValueError(f"Invalid regex in filter {rule['name']}: {exc}") from exc


def run_curl(source: str, temporary: str, args: list[str]) -> None:
    # Keep the output argument fixed; the UI cannot redirect writes elsewhere.
    command = ["curl", "--fail", "--silent", "--show-error", "--location",
               "--max-redirs", "5", "--proto", "=http,https,file", *args,
               "--output", temporary, "--", source]
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=180)
    if completed.returncode:
        message = (completed.stderr or f"curl exited with status {completed.returncode}").strip()
        raise RuntimeError(message[-500:])


def xml_field(record: ET.Element, field: str) -> str | None:
    if field in record.attrib:
        return record.get(field)
    if field in {"$text", "."}:
        return "".join(record.itertext())
    child = record.find(field)
    if child is not None:
        return "".join(child.itertext())
    return None


def matching_xml_records(path: str, options: dict[str, Any], tolerate_bad_xml: bool = False) -> set[tuple[str, ...]]:
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError:
        return set()
    except ET.ParseError:
        if tolerate_bad_xml:
            return set()
        raise
    record_tag = options.get("record_tag", "message")
    identity_fields = options.get("identity_fields", ["time", "text"])
    filters = options.get("filters", [])
    found: set[tuple[str, ...]] = set()
    for record in root.iter(record_tag):
        matched = False
        for rule in filters:
            candidate = xml_field(record, rule["field"])
            if candidate is None:
                continue
            pattern = rule["value"]
            flags = re.IGNORECASE if rule.get("ignore_case", True) else 0
            if rule["match"] == "contains":
                matched = pattern.casefold() in candidate.casefold() if rule.get("ignore_case", True) else pattern in candidate
            else:
                matched = re.search(pattern, candidate, flags) is not None
            if matched:
                break
        if not matched:
            continue
        identity = tuple(xml_field(record, field) or "" for field in identity_fields)
        if not any(identity):
            identity = (ET.tostring(record, encoding="unicode"),)
        found.add(identity)
    return found


def content_matches(text: str, filters: list[dict[str, Any]]) -> bool:
    for rule in filters:
        ignore_case = rule.get("ignore_case", True)
        flags = re.IGNORECASE if ignore_case else 0
        if rule["match"] == "contains":
            needle = rule["value"].casefold() if ignore_case else rule["value"]
            haystack = text.casefold() if ignore_case else text
            if needle in haystack:
                return True
        elif re.search(rule["value"], text, flags):
            return True
    return False


def run_job(job: dict[str, Any]) -> dict[str, Any]:
    destination = checked_destination(job["destination"])
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(fd)
    try:
        run_curl(job["source"], temporary, job.get("args", []))
        if job.get("handler", "download") == "xml_event_filter":
            options = job.get("options", {})
            feed_events = matching_xml_records(temporary, options)
            if not feed_events:
                return {"id": job["id"], "status": "skipped", "message": "No XML record matched the filters; existing file kept."}
            existing = matching_xml_records(str(destination), options, tolerate_bad_xml=True)
            if feed_events.issubset(existing):
                return {"id": job["id"], "status": "skipped", "message": "No new matching XML record; existing file kept."}
        elif job.get("handler", "download") == "content_filter":
            if os.path.getsize(temporary) > MAX_FILTER_BYTES:
                raise ValueError(f"Text filtering is limited to {MAX_FILTER_BYTES // (1024 * 1024)} MiB files.")
            text = Path(temporary).read_text(encoding="utf-8")
            if not content_matches(text, job.get("options", {}).get("filters", [])):
                return {"id": job["id"], "status": "skipped", "message": "No text filter matched; existing file kept."}
        os.chmod(temporary, int(job.get("mode", "0644"), 8) if isinstance(job.get("mode", "0644"), str) else job.get("mode", 0o644))
        os.replace(temporary, destination)
        return {"id": job["id"], "status": "copied", "message": f"Updated {destination}"}
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


async def execute_jobs() -> list[dict[str, Any]]:
    if run_lock.locked():
        raise HTTPException(status_code=409, detail="A run is already in progress.")
    async with run_lock:
        state["running"] = True
        started = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        results = []
        try:
            for job in config_read().get("jobs", []):
                try:
                    result = await asyncio.to_thread(run_job, job)
                except Exception as exc:
                    result = {"id": job.get("id", "?"), "status": "error", "message": str(exc)}
                results.append(result)
            state["last_run"] = started
            state["results"] = results[-100:]
            return results
        finally:
            state["running"] = False


async def scheduler() -> None:
    while True:
        try:
            delay = config_read().get("interval_minutes", DEFAULT_INTERVAL) * 60
        except Exception:
            delay = DEFAULT_INTERVAL * 60
        await asyncio.sleep(delay)
        try:
            await execute_jobs()
        except Exception as exc:
            state["results"] = [{"id": "scheduler", "status": "error", "message": str(exc)}]


@asynccontextmanager
async def lifespan(_: FastAPI):
    if not USERNAME or ":" in USERNAME:
        raise RuntimeError("SIPHON_USERNAME must be non-empty and cannot contain a colon.")
    if not PASSWORD:
        raise RuntimeError("Set SIPHON_PASSWORD before starting the app.")
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        config_write(default_config())
    task = asyncio.create_task(scheduler())
    if RUN_ON_START:
        asyncio.create_task(execute_jobs())
    yield
    task.cancel()


api = FastAPI(title="Siphon", lifespan=lifespan)


def require_login(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    valid_user = hmac.compare_digest(credentials.username.encode(), USERNAME.encode())
    valid_password = hmac.compare_digest(credentials.password.encode(), PASSWORD.encode())
    if not (valid_user and valid_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password.",
                            headers={"WWW-Authenticate": "Basic"})
    return credentials.username


@api.get("/")
async def home(_: str = Depends(require_login)):
    page = Path(__file__).with_name("index.html").read_text(encoding="utf-8")
    page = page.replace("__SIPHON_ICON_URL__", html.escape(ICON_URL, quote=True))
    return HTMLResponse(page)


@api.get("/icon.png")
async def icon(_: str = Depends(require_login)):
    return FileResponse(Path(__file__).with_name("siphon.png"), media_type="image/png")


@api.get("/api/config")
async def get_config(_: str = Depends(require_login)):
    return JSONResponse(config_read())


@api.put("/api/config")
async def put_config(request: Request, _: str = Depends(require_login)):
    try:
        value = await request.json()
        validate_config(value)
        config_write(value)
        return {"saved": True, "config": value}
    except (ValueError, yaml.YAMLError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@api.get("/api/status")
async def get_status(_: str = Depends(require_login)):
    return state


@api.post("/api/run")
async def run_now(_: str = Depends(require_login)):
    return {"results": await execute_jobs()}
