from collections import Counter
from dataclasses import asdict
from collections import deque
from datetime import datetime
from functools import wraps
from pathlib import Path
from threading import Event, Lock
from threading import Thread
from time import monotonic
from typing import Callable
from uuid import uuid4
import sqlite3
import re
import json
from urllib.parse import unquote, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask import Flask, Response, flash, redirect, render_template, request, session, stream_with_context, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from m3u_plus import IPTVEntry, parse_m3u_plus


app = Flask(__name__)
app.secret_key = "dev-change-me"

CATALOG: dict[str, IPTVEntry] = {}
DEFAULT_CLIENT_UA = "IPTV Smarters Pro/4.0.0"
PLAYLIST_FETCH_UA = "SmartIPTV/2.1.45 (Linux; Tizen 4.0) SIPTV"
BUFFER_DELAY_SECONDS = 60
BUFFER_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_PLAYLIST_URL = ""
DEFAULT_PLAYLIST_LOADED = False
PLAYLIST_STORAGE_DIR = Path(app.root_path) / "downloaded_playlists"
PLAYLIST_HISTORY_DIR = PLAYLIST_STORAGE_DIR / "history"
PLAYLIST_LATEST_PATH = PLAYLIST_STORAGE_DIR / "playlist_latest.m3u"
PLAYLIST_CONFIG_PATH = PLAYLIST_STORAGE_DIR / "playlist_config.json"
STREAM_LOCK = Lock()
ACTIVE_STREAMS: dict[str, tuple[str, Event]] = {}
LIVE_STREAM_KEY = "global-live"
CURRENT_LIVE_ENTRY_ID: str | None = None
PLAYLIST_DOWNLOAD_LOCK = Lock()
PLAYLIST_DOWNLOAD_STATE: dict[str, str | bool | None] = {
    "running": False,
    "started_at": None,
    "finished_at": None,
    "ok": None,
    "message": "",
}
USERS_DB_PATH = Path(app.root_path) / "users.db"
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"
USER_ROLES = {"admin", "user"}
USERS_READY = False


def _db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(USERS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_user_store() -> None:
    global USERS_READY
    if USERS_READY:
        return

    USERS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with _db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        existing = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        user_count = int(existing["count"] if existing else 0)

        if user_count == 0:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (
                    DEFAULT_ADMIN_USERNAME,
                    generate_password_hash(DEFAULT_ADMIN_PASSWORD),
                    "admin",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
            app.logger.warning(
                "Created default admin user (%s / %s). Change password after first login.",
                DEFAULT_ADMIN_USERNAME,
                DEFAULT_ADMIN_PASSWORD,
            )

    USERS_READY = True


def _row_to_user_dict(row: sqlite3.Row | None) -> dict[str, str | int] | None:
    if not row:
        return None

    return {
        "id": int(row["id"]),
        "username": str(row["username"]),
        "role": str(row["role"]),
        "created_at": str(row["created_at"]),
    }


def _get_user_by_username(username: str) -> dict[str, str | int] | None:
    with _db_connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return _row_to_user_dict(row)


def _get_user_with_password_by_username(username: str) -> sqlite3.Row | None:
    with _db_connect() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def _get_user_by_id(user_id: int) -> dict[str, str | int] | None:
    with _db_connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _row_to_user_dict(row)


def _list_users() -> list[dict[str, str | int]]:
    with _db_connect() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY username COLLATE NOCASE").fetchall()
    return [item for row in rows if (item := _row_to_user_dict(row)) is not None]


def _create_user(username: str, password: str, role: str) -> tuple[bool, str]:
    username = username.strip()
    role = role.strip().lower()

    if len(username) < 3:
        return False, "Username must be at least 3 characters"

    if len(password) < 6:
        return False, "Password must be at least 6 characters"

    if role not in USER_ROLES:
        return False, "Invalid role"

    try:
        with _db_connect() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), role, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )
    except sqlite3.IntegrityError:
        return False, "Username already exists"

    return True, "User created"


def _delete_user(user_id: int, actor_user_id: int) -> tuple[bool, str]:
    with _db_connect() as conn:
        target = conn.execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return False, "User not found"

        if int(target["id"]) == actor_user_id:
            return False, "You cannot delete your own account"

        if str(target["role"]) == "admin":
            admin_count = conn.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").fetchone()
            total_admins = int(admin_count["count"] if admin_count else 0)
            if total_admins <= 1:
                return False, "Cannot delete the last admin"

        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    return True, "User deleted"


def _update_user_password(
    user_id: int,
    new_password: str,
    actor_user_id: int,
    require_current_password: bool = False,
    current_password: str = "",
) -> tuple[bool, str]:
    if len(new_password) < 6:
        return False, "Password must be at least 6 characters"

    with _db_connect() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return False, "User not found"

        if require_current_password:
            if int(target["id"]) != actor_user_id:
                return False, "You can only change your own password"

            if not check_password_hash(str(target["password_hash"]), current_password):
                return False, "Current password is incorrect"

        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )

    return True, "Password updated"


def _current_user() -> dict[str, str | int] | None:
    user_id = session.get("user_id")
    if not user_id:
        return None

    try:
        parsed_user_id = int(user_id)
    except (TypeError, ValueError):
        session.pop("user_id", None)
        return None

    user = _get_user_by_id(parsed_user_id)
    if not user:
        session.pop("user_id", None)
        return None

    return user


def login_required(view_func: Callable):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not _current_user():
            flash("Please login first", "error")
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapped


def admin_required(view_func: Callable):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        user = _current_user()
        if not user:
            flash("Please login first", "error")
            return redirect(url_for("login", next=request.path))

        if str(user["role"]) != "admin":
            flash("Admin access required", "error")
            return redirect(url_for("library"))

        return view_func(*args, **kwargs)

    return wrapped


def _playlist_fetch_headers(user_agent: str) -> dict[str, str]:
    return {
        "User-Agent": user_agent,
    }


def _configured_playlist_url() -> str:
    if not PLAYLIST_CONFIG_PATH.exists():
        return DEFAULT_PLAYLIST_URL

    try:
        payload = json.loads(PLAYLIST_CONFIG_PATH.read_text(encoding="utf-8"))
        configured = str(payload.get("playlist_url", "")).strip()
        if configured:
            return configured
    except Exception:
        app.logger.exception("Failed to read playlist config file")

    return DEFAULT_PLAYLIST_URL


def _save_configured_playlist_url(playlist_url: str) -> None:
    PLAYLIST_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"playlist_url": playlist_url.strip()}
    PLAYLIST_CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _update_playlist_download_state(*, running: bool, ok: bool | None, message: str) -> None:
    with PLAYLIST_DOWNLOAD_LOCK:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if running:
            PLAYLIST_DOWNLOAD_STATE["started_at"] = now
            PLAYLIST_DOWNLOAD_STATE["finished_at"] = None
        else:
            PLAYLIST_DOWNLOAD_STATE["finished_at"] = now

        PLAYLIST_DOWNLOAD_STATE["running"] = running
        PLAYLIST_DOWNLOAD_STATE["ok"] = ok
        PLAYLIST_DOWNLOAD_STATE["message"] = message


def _get_playlist_download_state() -> dict[str, str | bool | None]:
    with PLAYLIST_DOWNLOAD_LOCK:
        return dict(PLAYLIST_DOWNLOAD_STATE)


def _fetch_remote_playlist(remote_url: str) -> str:
    session = requests.Session()
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=0.6,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    response = session.get(
        remote_url,
        headers=_playlist_fetch_headers(PLAYLIST_FETCH_UA),
        timeout=(10, 120),
        allow_redirects=True,
        verify=True,
    )
    response.raise_for_status()
    response.encoding = response.encoding or response.apparent_encoding or "utf-8"
    return response.text


def _save_playlist_content_to_disk(content: str) -> None:
    PLAYLIST_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    PLAYLIST_HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    temp_latest = PLAYLIST_STORAGE_DIR / f"playlist_latest_{uuid4().hex}.tmp"
    temp_latest.write_text(content, encoding="utf-8")
    temp_latest.replace(PLAYLIST_LATEST_PATH)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    history_path = PLAYLIST_HISTORY_DIR / f"playlist_{timestamp}.m3u"
    history_path.write_text(content, encoding="utf-8")


def _download_default_playlist_to_disk() -> str:
    content = _fetch_remote_playlist(_configured_playlist_url())

    _save_playlist_content_to_disk(content)

    app.logger.info("Default playlist downloaded to %s", PLAYLIST_LATEST_PATH)
    return content


def _load_playlist_content_from_disk() -> str:
    return PLAYLIST_LATEST_PATH.read_text(encoding="utf-8")


def _load_default_playlist_into_catalog() -> int:
    if PLAYLIST_LATEST_PATH.exists() and PLAYLIST_LATEST_PATH.stat().st_size > 0:
        content = _load_playlist_content_from_disk()
        app.logger.info("Using existing local playlist file at %s", PLAYLIST_LATEST_PATH)
    else:
        configured_url = _configured_playlist_url()
        if not configured_url:
            app.logger.info("No playlist URL configured yet. Waiting for admin playlist setup.")
            CATALOG.clear()
            return 0
        content = _download_default_playlist_to_disk()

    entries = parse_m3u_plus(content)

    CATALOG.clear()
    for entry in entries:
        CATALOG[entry.id] = entry

    return len(entries)


def _run_playlist_download_job(playlist_url: str) -> None:
    global DEFAULT_PLAYLIST_LOADED

    _update_playlist_download_state(running=True, ok=None, message="Downloading playlist in background...")
    try:
        content = _fetch_remote_playlist(playlist_url)
        entries = parse_m3u_plus(content)
        if not entries:
            raise ValueError("Downloaded playlist is empty")

        _save_playlist_content_to_disk(content)

        CATALOG.clear()
        for entry in entries:
            CATALOG[entry.id] = entry
        DEFAULT_PLAYLIST_LOADED = True

        _update_playlist_download_state(
            running=False,
            ok=True,
            message=f"Playlist updated successfully ({len(entries)} entries)",
        )
        app.logger.info("Background playlist update successful with %s entries", len(entries))
    except Exception as exc:
        _update_playlist_download_state(running=False, ok=False, message=f"Playlist update failed: {exc}")
        app.logger.exception("Background playlist update failed")


def _start_background_playlist_download(playlist_url: str) -> tuple[bool, str]:
    url = playlist_url.strip()
    if not url:
        return False, "Playlist URL is required"

    state = _get_playlist_download_state()
    if bool(state.get("running")):
        return False, "A playlist download is already running"

    _save_configured_playlist_url(url)

    worker = Thread(target=_run_playlist_download_job, args=(url,), daemon=True)
    worker.start()
    return True, "Playlist download started in background"


def _get_playlist_download_status() -> dict[str, str] | None:
    if not PLAYLIST_LATEST_PATH.exists():
        return None

    stat = PLAYLIST_LATEST_PATH.stat()
    return {
        "path": str(PLAYLIST_LATEST_PATH),
        "downloaded_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "size_kb": f"{stat.st_size / 1024:.1f}",
    }


def _entry_country(entry: IPTVEntry) -> str:
    group_parts = [part.strip() for part in (entry.group_title or "").split("|") if part.strip()]

    raw_country = (
        entry.raw_attrs.get("tvg-country")
        or entry.raw_attrs.get("country")
        or entry.raw_attrs.get("tvg-country-code")
        or ""
    ).strip()
    if raw_country:
        return raw_country.upper()

    if len(group_parts) >= 3:
        return group_parts[1].upper()

    token_sources = [entry.tvg_name or "", entry.title or ""]
    for token_source in token_sources:
        match = re.search(r"[A-Z0-9]+-\s*([A-Z]{2,5})\s*(?=\|)", token_source, flags=re.IGNORECASE)
        if match:
            return match.group(1).upper()

    return "Unknown"


def _entry_region(entry: IPTVEntry) -> str:
    group_parts = [part.strip() for part in (entry.group_title or "").split("|") if part.strip()]
    if group_parts:
        region_token = group_parts[0].strip().upper()
        region_aliases = {
            "EU": "EU",
            "EUR": "EU",
            "EUROPE": "EU",
            "AF": "AF",
            "AFR": "AF",
            "AFRICA": "AF",
            "US": "US",
            "USA": "US",
            "AMERICA": "US",
            "AS": "AS",
            "ASIA": "AS",
            "LATAM": "LATAM",
            "LA": "LATAM",
            "OC": "OC",
            "OCEANIA": "OC",
        }
        if region_token in region_aliases:
            return region_aliases[region_token]

    country = _entry_country(entry).strip().lower()
    if not country or country == "unknown":
        return "Unknown"

    us_tokens = {"us", "usa", "united states", "united states of america"}
    af_tokens = {
        "dz", "algeria", "ao", "angola", "bj", "benin", "bw", "botswana", "bf", "burkina faso",
        "bi", "burundi", "cm", "cameroon", "cv", "cape verde", "td", "chad", "km", "comoros",
        "cg", "congo", "cd", "dr congo", "dj", "djibouti", "eg", "egypt", "gq", "equatorial guinea",
        "er", "eritrea", "sz", "eswatini", "et", "ethiopia", "ga", "gabon", "gm", "gambia", "gh", "ghana",
        "gn", "guinea", "gw", "guinea-bissau", "ci", "ivory coast", "ke", "kenya", "ls", "lesotho", "lr", "liberia",
        "ly", "libya", "mg", "madagascar", "mw", "malawi", "ml", "mali", "mr", "mauritania", "mu", "mauritius",
        "yt", "mayotte", "ma", "morocco", "mz", "mozambique", "na", "namibia", "ne", "niger", "ng", "nigeria",
        "re", "reunion", "rw", "rwanda", "st", "sao tome", "sn", "senegal", "sc", "seychelles", "sl", "sierra leone",
        "so", "somalia", "za", "south africa", "ss", "south sudan", "sd", "sudan", "tz", "tanzania", "tg", "togo",
        "tn", "tunisia", "ug", "uganda", "zm", "zambia", "zw", "zimbabwe"
    }
    eu_tokens = {
        "al", "albania", "ad", "andorra", "at", "austria", "by", "belarus", "be", "belgium", "ba", "bosnia",
        "bg", "bulgaria", "hr", "croatia", "cy", "cyprus", "cz", "czechia", "dk", "denmark", "ee", "estonia",
        "fi", "finland", "fr", "france", "de", "germany", "gr", "greece", "hu", "hungary", "is", "iceland",
        "ie", "ireland", "it", "italy", "xk", "kosovo", "lv", "latvia", "li", "liechtenstein", "lt", "lithuania",
        "lu", "luxembourg", "mt", "malta", "md", "moldova", "mc", "monaco", "me", "montenegro", "nl", "netherlands",
        "mk", "north macedonia", "no", "norway", "pl", "poland", "pt", "portugal", "ro", "romania", "ru", "russia",
        "sm", "san marino", "rs", "serbia", "sk", "slovakia", "si", "slovenia", "es", "spain", "sw", "sweden",
        "ch", "switzerland", "tr", "turkey", "ua", "ukraine", "gb", "uk", "united kingdom", "va", "vatican"
    }
    as_tokens = {
        "ae", "united arab emirates", "af", "afghanistan", "am", "armenia", "az", "azerbaijan", "bd", "bangladesh",
        "bh", "bahrain", "bn", "brunei", "bt", "bhutan", "cn", "china", "ge", "georgia", "hk", "hong kong",
        "id", "indonesia", "in", "india", "iq", "iraq", "ir", "iran", "il", "israel", "jp", "japan", "jo", "jordan",
        "kg", "kyrgyzstan", "kh", "cambodia", "kp", "north korea", "kr", "south korea", "kw", "kuwait", "kz", "kazakhstan",
        "la", "laos", "lb", "lebanon", "lk", "sri lanka", "mm", "myanmar", "mn", "mongolia", "mo", "macao", "mv", "maldives",
        "my", "malaysia", "np", "nepal", "om", "oman", "ph", "philippines", "pk", "pakistan", "ps", "palestine",
        "qa", "qatar", "sa", "saudi arabia", "sg", "singapore", "sy", "syria", "th", "thailand", "tj", "tajikistan",
        "tl", "timor-leste", "tm", "turkmenistan", "tw", "taiwan", "uz", "uzbekistan", "vn", "vietnam", "ye", "yemen"
    }
    latam_tokens = {
        "ar", "argentina", "bo", "bolivia", "br", "brazil", "cl", "chile", "co", "colombia", "cr", "costa rica",
        "cu", "cuba", "do", "dominican republic", "ec", "ecuador", "sv", "el salvador", "gt", "guatemala", "hn", "honduras",
        "mx", "mexico", "ni", "nicaragua", "pa", "panama", "py", "paraguay", "pe", "peru", "pr", "puerto rico",
        "uy", "uruguay", "ve", "venezuela"
    }
    oc_tokens = {
        "au", "australia", "nz", "new zealand", "fj", "fiji", "pg", "papua new guinea", "ws", "samoa", "to", "tonga", "vu", "vanuatu"
    }

    if country in us_tokens:
        return "US"
    if country in eu_tokens:
        return "EU"
    if country in af_tokens:
        return "AF"
    if country in as_tokens:
        return "AS"
    if country in latam_tokens:
        return "LATAM"
    if country in oc_tokens:
        return "OC"
    return "Other"


def _entry_folder_type(entry: IPTVEntry) -> str:
    group_parts = [part.strip() for part in (entry.group_title or "").split("|") if part.strip()]
    if group_parts:
        return group_parts[-1]
    return "Uncategorized"


def _ensure_default_playlist_loaded() -> None:
    global DEFAULT_PLAYLIST_LOADED
    if DEFAULT_PLAYLIST_LOADED:
        return

    count = _load_default_playlist_into_catalog()
    DEFAULT_PLAYLIST_LOADED = True
    app.logger.info("Default playlist loaded with %s streams", count)


def _get_or_create_client_id() -> str:
    client_id = session.get("client_id")
    if client_id:
        return str(client_id)

    client_id = uuid4().hex
    session["client_id"] = client_id
    return client_id


def _register_active_stream_for_key(client_key: str) -> tuple[str, Event]:
    connection_id = uuid4().hex
    cancel_event = Event()

    with STREAM_LOCK:
        previous = ACTIVE_STREAMS.get(client_key)
        if previous:
            previous[1].set()
        ACTIVE_STREAMS[client_key] = (connection_id, cancel_event)

    return connection_id, cancel_event


def _register_active_stream_for_client() -> tuple[str, str, Event]:
    client_id = _get_or_create_client_id()
    connection_id, cancel_event = _register_active_stream_for_key(client_id)

    return client_id, connection_id, cancel_event


def _get_active_stream_for_key(client_key: str) -> tuple[str, Event] | None:
    with STREAM_LOCK:
        return ACTIVE_STREAMS.get(client_key)


def _release_active_stream_for_key(client_key: str, connection_id: str) -> None:
    with STREAM_LOCK:
        current = ACTIVE_STREAMS.get(client_key)
        if current and current[0] == connection_id:
            del ACTIVE_STREAMS[client_key]


def _release_active_stream_for_client(client_id: str, connection_id: str) -> None:
    _release_active_stream_for_key(client_id, connection_id)


def _set_current_live_entry(entry_id: str) -> bool:
    global CURRENT_LIVE_ENTRY_ID

    entry = CATALOG.get(entry_id)
    if not entry:
        return False

    CURRENT_LIVE_ENTRY_ID = entry_id
    current = _get_active_stream_for_key(LIVE_STREAM_KEY)
    if current:
        current[1].set()
    return True


def _stop_current_live_stream() -> bool:
    global CURRENT_LIVE_ENTRY_ID

    stopped = False
    with STREAM_LOCK:
        current = ACTIVE_STREAMS.pop(LIVE_STREAM_KEY, None)

    if current:
        current[1].set()
        stopped = True

    if CURRENT_LIVE_ENTRY_ID is not None:
        CURRENT_LIVE_ENTRY_ID = None
        stopped = True

    return stopped


def _get_current_live_entry() -> IPTVEntry | None:
    if not CURRENT_LIVE_ENTRY_ID:
        return None
    return CATALOG.get(CURRENT_LIVE_ENTRY_ID)


@app.context_processor
def inject_current_live_entry():
    return {
        "current_live_entry": _get_current_live_entry(),
        "current_user": _current_user(),
    }


@app.before_request
def ensure_user_store_before_requests():
    _init_user_store()


@app.get("/")
@login_required
def root():
    return redirect(url_for("library"))


@app.before_request
def ensure_playlist_before_requests():
    global DEFAULT_PLAYLIST_LOADED
    if DEFAULT_PLAYLIST_LOADED:
        return

    try:
        _ensure_default_playlist_loaded()
    except Exception as exc:
        flash(f"Failed to load default playlist: {exc}", "error")
        app.logger.exception("Failed to load default playlist")


@app.get("/library")
@login_required
def library():
    saved_filters = session.get("library_filters", {})

    selected_type = request.args.get("type")
    if selected_type is None:
        selected_type = str(saved_filters.get("type", "tv"))

    selected_region = request.args.get("region")
    if selected_region is None:
        selected_region = str(saved_filters.get("region", "all"))
    selected_region = selected_region.strip() or "all"

    selected_folder = request.args.get("folder")
    if selected_folder is None:
        selected_folder = str(saved_filters.get("folder", "all"))
    selected_folder = selected_folder.strip() or "all"

    query = request.args.get("q")
    if query is None:
        query = str(saved_filters.get("q", ""))
    query = query.strip().lower()

    if selected_type not in {"tv", "movies", "series"}:
        selected_type = "tv"

    session["library_filters"] = {
        "type": selected_type,
        "region": selected_region,
        "folder": selected_folder,
        "q": query,
    }

    entries = list(CATALOG.values())
    counts = Counter(item.category for item in entries)

    if selected_type in {"tv", "movies", "series"}:
        entries = [item for item in entries if item.category == selected_type]

    region_counts = Counter(_entry_region(item) for item in entries)

    if selected_region != "all":
        entries = [item for item in entries if _entry_region(item) == selected_region]

    folder_counts = Counter(_entry_folder_type(item) for item in entries)

    if selected_folder != "all":
        entries = [item for item in entries if _entry_folder_type(item) == selected_folder]

    if query:
        entries = [
            item
            for item in entries
            if query in item.title.lower() or query in item.group_title.lower() or query in item.stream_url.lower()
        ]

    entries.sort(key=lambda item: (item.group_title.lower(), item.title.lower()))

    return render_template(
        "library.html",
        entries=entries,
        selected_type=selected_type,
        selected_region=selected_region,
        selected_folder=selected_folder,
        regions=sorted(region_counts.items(), key=lambda item: item[0].lower()),
        folders=sorted(folder_counts.items(), key=lambda item: item[0].lower()),
        counts=counts,
        query=query,
        total=len(CATALOG),
    )


@app.get("/watch/<entry_id>")
@login_required
def watch(entry_id: str):
    if not _set_current_live_entry(entry_id):
        flash("Stream not found", "error")
        return redirect(url_for("library"))

    return redirect(url_for("player_live"))


@app.get("/watch/live")
@login_required
def watch_live():
    entry = _get_current_live_entry()
    if not entry:
        flash("Stream not found", "error")
        return redirect(url_for("library"))

    return redirect(url_for("player_live"))


@app.get("/player/live")
@login_required
def player_live():
    entry = _get_current_live_entry()
    if not entry:
        flash("No live channel selected", "error")
        return redirect(url_for("library"))

    stream_src = url_for("proxy_stream_live")
    stream_url = url_for("proxy_stream_live", _external=True)
    return render_template("watch.html", entry=entry, stream_src=stream_src, stream_url=stream_url)


@app.post("/live/stop")
@login_required
def stop_live():
    if _stop_current_live_stream():
        flash("Live stream stopped", "success")
    else:
        flash("No live stream to stop", "error")
    return redirect(url_for("library"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if _current_user():
        return redirect(url_for("library"))

    next_url = request.args.get("next", "")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next", "")

        user_row = _get_user_with_password_by_username(username)
        if not user_row or not check_password_hash(str(user_row["password_hash"]), password):
            flash("Invalid username or password", "error")
            return render_template("login.html", next_url=next_url)

        session["user_id"] = int(user_row["id"])
        flash("Welcome", "success")

        if next_url.startswith("/"):
            return redirect(next_url)
        return redirect(url_for("library"))

    return render_template("login.html", next_url=next_url)


@app.post("/logout")
@login_required
def logout():
    session.pop("user_id", None)
    flash("Logged out", "success")
    return redirect(url_for("login"))


@app.get("/account")
@login_required
def account():
    user = _current_user()
    if not user:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    return render_template("account.html", user=user)


@app.post("/account/password")
@login_required
def account_change_password():
    user = _current_user()
    if not user:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if new_password != confirm_password:
        flash("New passwords do not match", "error")
        return redirect(url_for("account"))

    ok, message = _update_user_password(
        user_id=int(user["id"]),
        new_password=new_password,
        actor_user_id=int(user["id"]),
        require_current_password=True,
        current_password=current_password,
    )
    flash(message, "success" if ok else "error")
    return redirect(url_for("account"))


@app.get("/admin/users")
@admin_required
def admin_users():
    return render_template("users.html", users=_list_users())


@app.post("/admin/users")
@admin_required
def admin_create_user():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    role = request.form.get("role", "user")

    ok, message = _create_user(username=username, password=password, role=role)
    flash(message, "success" if ok else "error")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:user_id>/delete")
@admin_required
def admin_delete_user(user_id: int):
    actor = _current_user()
    if not actor:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    ok, message = _delete_user(user_id=user_id, actor_user_id=int(actor["id"]))
    flash(message, "success" if ok else "error")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:user_id>/password")
@admin_required
def admin_update_user_password(user_id: int):
    actor = _current_user()
    if not actor:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    new_password = request.form.get("new_password", "")
    ok, message = _update_user_password(
        user_id=user_id,
        new_password=new_password,
        actor_user_id=int(actor["id"]),
        require_current_password=False,
    )
    flash(message, "success" if ok else "error")
    return redirect(url_for("admin_users"))


@app.get("/admin/playlist")
@admin_required
def admin_playlist():
    return render_template(
        "admin_playlist.html",
        playlist_url=_configured_playlist_url(),
        download_status=_get_playlist_download_state(),
    )


@app.post("/admin/playlist")
@admin_required
def admin_playlist_update():
    playlist_url = request.form.get("playlist_url", "").strip()
    ok, message = _start_background_playlist_download(playlist_url)
    flash(message, "success" if ok else "error")
    return redirect(url_for("admin_playlist"))


@app.get("/api/admin/playlist/status")
@admin_required
def api_admin_playlist_status():
    return {
        "ok": True,
        "status": _get_playlist_download_state(),
        "playlist_url": _configured_playlist_url(),
    }


def _upstream_headers(target: str, entry_headers: dict[str, str] | None = None) -> dict[str, str]:
    parsed = urlparse(target)
    origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""

    headers: dict[str, str] = {
        "User-Agent": DEFAULT_CLIENT_UA,
        "Accept": "*/*",
        "Connection": "keep-alive",
    }

    if origin:
        headers["Origin"] = origin
        headers["Referer"] = f"{origin}/"

    if entry_headers:
        for key, value in entry_headers.items():
            if key and value:
                headers[key] = value

    if "Range" in request.headers:
        headers["Range"] = request.headers["Range"]

    return headers


def _is_manifest_response(target: str, upstream: requests.Response) -> bool:
    content_type = upstream.headers.get("Content-Type", "").lower()
    return ".m3u8" in target.lower() or "mpegurl" in content_type


def _rewrite_manifest(
    content: str,
    base_url: str,
    entry_id: str | None,
    rewrite_endpoint: str | None = None,
    rewrite_params: dict[str, str] | None = None,
) -> str:
    extra_params = dict(rewrite_params or {})
    rewritten: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()

        if not stripped:
            rewritten.append(line)
            continue

        if stripped.startswith("#EXT-X-KEY") or stripped.startswith("#EXT-X-MAP"):
            if 'URI="' in line:
                prefix, tail = line.split('URI="', 1)
                uri_value, suffix = tail.split('"', 1)
                absolute = urljoin(base_url, uri_value)
                if rewrite_endpoint:
                    proxied = url_for(rewrite_endpoint, target=absolute, **extra_params)
                elif entry_id:
                    proxied = url_for("proxy_stream_entry", entry_id=entry_id, target=absolute)
                else:
                    proxied = url_for("proxy_stream", target=absolute)
                rewritten.append(f'{prefix}URI="{proxied}"{suffix}')
            else:
                rewritten.append(line)
            continue

        if stripped.startswith("#"):
            rewritten.append(line)
            continue

        absolute = urljoin(base_url, stripped)
        if rewrite_endpoint:
            proxied = url_for(rewrite_endpoint, target=absolute, **extra_params)
        elif entry_id:
            proxied = url_for("proxy_stream_entry", entry_id=entry_id, target=absolute)
        else:
            proxied = url_for("proxy_stream", target=absolute)
        rewritten.append(proxied)

    return "\n".join(rewritten)


def _delayed_stream_generator(upstream: requests.Response, delay_seconds: int, cancel_event: Event | None = None):
    pending_chunks = deque()
    buffered_bytes = 0
    started_at = None
    releasing = False

    for chunk in upstream.iter_content(chunk_size=64 * 1024):
        if cancel_event and cancel_event.is_set():
            break

        if not chunk:
            continue

        now = monotonic()
        if started_at is None:
            started_at = now

        pending_chunks.append(chunk)
        buffered_bytes += len(chunk)

        if not releasing:
            elapsed = now - started_at
            if elapsed >= delay_seconds or buffered_bytes >= BUFFER_MAX_BYTES:
                releasing = True

        if releasing and pending_chunks:
            out = pending_chunks.popleft()
            buffered_bytes -= len(out)
            yield out

    while pending_chunks:
        out = pending_chunks.popleft()
        yield out


def _passthrough_stream_generator(upstream: requests.Response, cancel_event: Event | None = None):
    for chunk in upstream.iter_content(chunk_size=64 * 1024):
        if cancel_event and cancel_event.is_set():
            break

        if chunk:
            yield chunk


def _proxy_to_target(
    target: str,
    entry_headers: dict[str, str] | None = None,
    entry_id: str | None = None,
    delayed_buffer_seconds: int = 0,
    cancel_event: Event | None = None,
    on_stream_end: Callable[[], None] | None = None,
    rewrite_endpoint: str | None = None,
    rewrite_params: dict[str, str] | None = None,
):
    target = unquote(target)
    try:
        upstream = requests.get(
            target,
            headers=_upstream_headers(target=target, entry_headers=entry_headers),
            stream=True,
            timeout=(10, 120),
            allow_redirects=True,
        )
    except requests.exceptions.Timeout:
        if on_stream_end:
            on_stream_end()
        app.logger.warning("Upstream timeout for target: %s", target)
        return Response("Upstream stream timed out", status=504)
    except requests.exceptions.RequestException as exc:
        if on_stream_end:
            on_stream_end()
        app.logger.warning("Upstream request failed for target %s: %s", target, exc)
        return Response("Failed to reach upstream stream", status=502)


    if upstream.status_code >= 400:
        return Response(f"Upstream error {upstream.status_code}", status=upstream.status_code)

    if _is_manifest_response(target=target, upstream=upstream):
        manifest_text = upstream.text
        rewritten_manifest = _rewrite_manifest(
            content=manifest_text,
            base_url=upstream.url,
            entry_id=entry_id,
            rewrite_endpoint=rewrite_endpoint,
            rewrite_params=rewrite_params,
        )
        upstream.close()
        if on_stream_end:
            on_stream_end()
        return Response(rewritten_manifest, status=upstream.status_code, content_type="application/vnd.apple.mpegurl")

    passthrough_headers = {}
    for key in ["Content-Type", "Content-Length", "Accept-Ranges", "Content-Range", "Cache-Control"]:
        if key in upstream.headers:
            passthrough_headers[key] = upstream.headers[key]

    if delayed_buffer_seconds > 0 and "Range" not in request.headers:
        base_generator = _delayed_stream_generator(
            upstream=upstream,
            delay_seconds=delayed_buffer_seconds,
            cancel_event=cancel_event,
        )
        passthrough_headers.pop("Content-Length", None)
    else:
        base_generator = _passthrough_stream_generator(upstream=upstream, cancel_event=cancel_event)

    def generate():
        try:
            for chunk in base_generator:
                yield chunk
        finally:
            upstream.close()
            if on_stream_end:
                on_stream_end()

    return Response(
        stream_with_context(generate()),
        status=upstream.status_code,
        headers=passthrough_headers,
        direct_passthrough=True,
    )


@app.get("/stream")
def proxy_stream():
    target = request.args.get("target", "")
    if not target:
        return Response("Missing target parameter", status=400)
    return _proxy_to_target(target=target)


@app.get("/stream/<entry_id>")
def proxy_stream_entry(entry_id: str):
    entry = CATALOG.get(entry_id)
    if not entry:
        return Response("Stream not found", status=404)
    nested_target = request.args.get("target")
    if nested_target:
        if session.get("active_entry_id") != entry_id:
            return Response("Stream replaced by a newer selection", status=409)
        return _proxy_to_target(target=nested_target, entry_headers=entry.stream_headers, entry_id=entry_id)

    session["active_entry_id"] = entry_id
    client_id, connection_id, cancel_event = _register_active_stream_for_client()

    return _proxy_to_target(
        target=entry.stream_url,
        entry_headers=entry.stream_headers,
        entry_id=entry_id,
        delayed_buffer_seconds=BUFFER_DELAY_SECONDS,
        cancel_event=cancel_event,
        on_stream_end=lambda: _release_active_stream_for_client(client_id, connection_id),
    )


@app.get("/stream/live")
def proxy_stream_live():
    global CURRENT_LIVE_ENTRY_ID

    if not CURRENT_LIVE_ENTRY_ID:
        return Response("No live channel selected", status=404)

    entry = CATALOG.get(CURRENT_LIVE_ENTRY_ID)
    if not entry:
        return Response("Selected live channel not found", status=404)

    nested_target = request.args.get("target")
    if nested_target:
        conn_id = request.args.get("conn", "")
        current = _get_active_stream_for_key(LIVE_STREAM_KEY)
        if not current or not conn_id or current[0] != conn_id:
            return Response("Stream replaced by a newer selection", status=409)

        return _proxy_to_target(
            target=nested_target,
            entry_headers=entry.stream_headers,
            entry_id=entry.id,
            cancel_event=current[1],
            rewrite_endpoint="proxy_stream_live",
            rewrite_params={"conn": conn_id},
        )

    connection_id, cancel_event = _register_active_stream_for_key(LIVE_STREAM_KEY)

    return _proxy_to_target(
        target=entry.stream_url,
        entry_headers=entry.stream_headers,
        entry_id=entry.id,
        delayed_buffer_seconds=BUFFER_DELAY_SECONDS,
        cancel_event=cancel_event,
        on_stream_end=lambda: _release_active_stream_for_key(LIVE_STREAM_KEY, connection_id),
        rewrite_endpoint="proxy_stream_live",
        rewrite_params={"conn": connection_id},
    )


@app.post("/api/live/select/<entry_id>")
@login_required
def api_select_live(entry_id: str):
    if not _set_current_live_entry(entry_id):
        return {"ok": False, "error": "Stream not found"}, 404

    return {"ok": True, "entry_id": entry_id}


@app.post("/api/live/stop")
@login_required
def api_stop_live():
    stopped = _stop_current_live_stream()
    return {"ok": True, "stopped": stopped, "entry_id": None}


@app.get("/api/live/current")
@login_required
def api_live_current():
    if not CURRENT_LIVE_ENTRY_ID:
        return {"ok": False, "entry_id": None}

    entry = CATALOG.get(CURRENT_LIVE_ENTRY_ID)
    if not entry:
        return {"ok": False, "entry_id": None}

    return {"ok": True, "entry_id": entry.id, "title": entry.title}


@app.get("/api/library")
@login_required
def api_library():
    payload = [asdict(item) for item in CATALOG.values()]
    return {"count": len(payload), "items": payload}


if __name__ == "__main__":
    try:
        _init_user_store()
        _ensure_default_playlist_loaded()
    except Exception:
        app.logger.exception("Startup default playlist load failed")
    app.run(debug=True, port=11001, host="0.0.0.0")
