import re
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional


EXTINF_RE = re.compile(r'^#EXTINF:(?P<duration>-?\d+)\s*(?P<attrs>.*?),(?P<title>.*)$')
ATTR_RE = re.compile(r'([\w\-]+)="(.*?)"')


@dataclass
class IPTVEntry:
    id: str
    title: str
    stream_url: str
    category: str
    group_title: str
    tvg_name: str
    tvg_id: str
    tvg_logo: str
    stream_headers: Dict[str, str]
    raw_attrs: Dict[str, str]


def _parse_stream_line(line: str) -> tuple[str, Dict[str, str]]:
    if "|" not in line:
        return line, {}

    stream_url, header_part = line.split("|", 1)
    headers: Dict[str, str] = {}
    for pair in header_part.split("&"):
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        key = key.strip().replace("+", " ").title()
        value = value.strip().replace("+", " ")
        if key and value:
            headers[key] = value
    return stream_url.strip(), headers


def _parse_extinf(line: str) -> Optional[dict]:
    match = EXTINF_RE.match(line.strip())
    if not match:
        return None

    attrs_text = match.group("attrs")
    attrs = {key.lower(): value for key, value in ATTR_RE.findall(attrs_text)}
    return {
        "duration": int(match.group("duration")),
        "title": match.group("title").strip(),
        "attrs": attrs,
    }


def _classify(title: str, group_title: str, stream_url: str) -> str:
    bucket = f"{title} {group_title} {stream_url}".lower()

    if any(word in bucket for word in [" series", "season", "episode", "tv show", "/series/"]):
        return "series"
    if any(word in bucket for word in ["movie", "vod", "film", "/movie/"]):
        return "movies"
    return "tv"


def parse_m3u_plus(content: str) -> List[IPTVEntry]:
    entries: List[IPTVEntry] = []
    pending = None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("#EXTINF"):
            pending = _parse_extinf(line)
            continue

        if line.startswith("#"):
            continue

        if pending is None:
            continue

        stream_url, stream_headers = _parse_stream_line(line)
        attrs = pending["attrs"]

        title = attrs.get("tvg-name") or pending["title"] or "Untitled"
        group_title = attrs.get("group-title", "Uncategorized")
        category = _classify(title=title, group_title=group_title, stream_url=stream_url)

        entries.append(
            IPTVEntry(
                id=uuid.uuid4().hex,
                title=title,
                stream_url=stream_url,
                category=category,
                group_title=group_title,
                tvg_name=attrs.get("tvg-name", ""),
                tvg_id=attrs.get("tvg-id", ""),
                tvg_logo=attrs.get("tvg-logo", ""),
                stream_headers=stream_headers,
                raw_attrs=attrs,
            )
        )
        pending = None

    return entries
