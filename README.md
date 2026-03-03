# IPTV Web Player

Web-based IPTV player built with Flask.

It supports browser playback, relays streams through a proxy, supports buffered streaming, and works with external players like VLC using the live stream URL.

## Features

- M3U Plus parsing (`#EXTM3U` / `#EXTINF` with attributes)
- Library split into TV / Movies / Series with search and filters
- Current live channel selection and shared live endpoint
- Browser player page for current stream
- External player support (VLC) via live stream URL
- Stream relay proxy with optional buffering and range passthrough
- Stop live stream action to stop pulling upstream data
- Role-based auth: `admin` and `user`
- Admin pages for user management and playlist source management
- Background playlist download with atomic replace (old playlist kept on failure)

## Tech Stack

- Python + Flask
- `requests` for upstream stream/playlist fetching
- Jinja templates + vanilla JS

## Quick Start

### 1) Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Run

```bash
python app.py
```

Open: `http://127.0.0.1:11001`

### 3) First Login

- Default admin user: `admin`
- Default password: `admin`

Change the password immediately from the Account page or create a new admin and remove the default one.

## Playlist Setup (Admin)

There is no hardcoded default playlist URL. Admin must configure it in the web UI:

- Go to `/admin/playlist`
- Enter playlist URL
- Click **Save and Download**

Download behavior:

- Runs in background
- Uses this exact User-Agent value:
	- `SmartIPTV/2.1.45 (Linux; Tizen 4.0) SIPTV`
- Replaces active playlist only after successful full download + parse

## Playback Modes

### Browser Player

- Select a channel with **Watch**
- Opens player page for current live stream (`/player/live`)

### VLC / External Players

- Use live stream endpoint:
	- `/stream/live`
- Example full URL:
	- `http://<server-ip>:11001/stream/live`

## Admin Pages

- User management: `/admin/users`
- Playlist source/status: `/admin/playlist`

## Notes

- This project is for streams you are authorized to access.
- Some providers may require specific client behavior and can block playback/proxying.
