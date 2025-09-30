"""
p74_youtube_helper.py

Submenu P74 - YouTube Link Helper & (SAH) Local Redirect Logger

FUNGSI:
- Parse/validasi link YouTube (ambil video id, tipe link: watch, youtu.be, embed)
- Opsional: fetch metadata via YouTube Data API (butuh API key milikmu)
- Contoh Flask redirect server yang LOGS kunjungan ke file lokal (HANYA untuk
  server yang kamu kendalikan dan bila visitor memberikan izin).
  - Opsi untuk menyimpan IP mentah atau hash(IP + salt) untuk anonimisasi.
  - Sangat penting: jangan gunakan untuk melacak pihak lain tanpa izin.

Dependencies:
    pip install requests rich Flask

USAGE:
- Jalankan sebagai modul terpisah atau import menu_youtube() ke menu utama.
"""

import os
import re
import json
import hashlib
import datetime
import socket
from urllib.parse import urlparse, parse_qs
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    clear_screen()
    console.print(
        Panel(
            "[bold blue]📺 YouTube - Link Helper & Local Redirect Logger[/bold blue]\n\n"
            "[white]Tool aman: parse link YouTube, ambil metadata via YouTube Data API (jika ada API key),\n"
            "dan contoh Flask redirect server untuk mencatat kunjungan pada server yang kamu kendalikan.\n\n"
            "[red]PENTING:[/red] Jangan gunakan server/redirect untuk melacak atau mengidentifikasi orang tanpa izin.\n"
            "Jika ragu, gunakan opsi hash/anonymize IP atau jangan catat IP sama sekali.[/white]",
            title="[bold cyan]🔥 Ninja Toolkit - Link Helper[/bold cyan]",
            box=box.DOUBLE,
            padding=(1, 2),
            border_style="blue",
        )
    )

# -------------------- YouTube link parsing --------------------

YOUTUBE_REGEXES = [
    # standard watch URL: https://www.youtube.com/watch?v=VIDEOID
    r'(?:https?://)?(?:www\.)?youtube\.com/watch\?.*v=([A-Za-z0-9_\-]{11})',
    # short youtu.be: https://youtu.be/VIDEOID
    r'(?:https?://)?(?:www\.)?youtu\.be/([A-Za-z0-9_\-]{11})',
    # embed url: https://www.youtube.com/embed/VIDEOID
    r'(?:https?://)?(?:www\.)?youtube\.com/embed/([A-Za-z0-9_\-]{11})',
    # attribution_link or other param-based links
    r'v=([A-Za-z0-9_\-]{11})'
]

def extract_video_id(url):
    """
    Kembalikan video_id (11 chars) jika ditemukan, atau None.
    """
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    # try regexes
    for rx in YOUTUBE_REGEXES:
        m = re.search(rx, url)
        if m:
            return m.group(1)
    # fallback: parse query
    try:
        p = urlparse(url)
        qs = parse_qs(p.query)
        v = qs.get("v")
        if v:
            candidate = v[0]
            if re.match(r'^[A-Za-z0-9_\-]{11}$', candidate):
                return candidate
    except Exception:
        pass
    return None

def display_link_info(url):
    vid = extract_video_id(url)
    table = Table(title="🔎 YouTube Link Info", box=box.SIMPLE)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Original URL", url)
    table.add_row("Video ID", vid or "-")
    table.add_row("Likely valid", "Yes" if vid else "No")
    console.print(table)
    return vid

# -------------------- YouTube Data API helper --------------------

def get_youtube_video_metadata(api_key, video_id):
    """
    Ambil metadata video via YouTube Data API v3 'videos' endpoint.
    Requires API key milikmu. Kembalikan dict atau None.
    NOTE: tanpa API key, fungsi ini tidak dipanggil.
    """
    if not api_key or not video_id:
        return None
    url = "https://www.googleapis.com/youtube/v3/videos"
    params = {
        "part": "snippet,contentDetails,statistics",
        "id": video_id,
        "key": api_key
    }
    try:
        resp = requests.get(url, params=params, timeout=10)
        if resp.status_code != 200:
            console.print(f"[red]YouTube API error: {resp.status_code} — {resp.text}[/red]")
            return None
        data = resp.json()
        items = data.get("items", [])
        if not items:
            console.print("[yellow]Tidak ditemukan video (mungkin ID salah atau video private/unavailable).[/yellow]")
            return None
        return items[0]  # return full item
    except requests.RequestException as e:
        console.print(f"[red]Network error saat memanggil YouTube API: {e}[/red]")
        return None

def show_video_metadata(item):
    if not item:
        console.print("[yellow]Tidak ada metadata untuk ditampilkan.[/yellow]")
        return
    snippet = item.get("snippet", {})
    stats = item.get("statistics", {})
    content = item.get("contentDetails", {})
    table = Table(title="📹 YouTube Video Metadata", box=box.MINIMAL)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Title", snippet.get("title", "-"))
    table.add_row("Channel", snippet.get("channelTitle", "-"))
    table.add_row("Published At", snippet.get("publishedAt", "-"))
    table.add_row("Duration", content.get("duration", "-"))
    table.add_row("View Count", stats.get("viewCount", "-"))
    table.add_row("Like Count", stats.get("likeCount", "-"))
    table.add_row("Comment Count", stats.get("commentCount", "-"))
    console.print(table)

# -------------------- Public IP helper (reuse concept from earlier) --------------------

def get_public_ip(timeout=6):
    try:
        resp = requests.get("https://api.ipify.org", params={"format": "text"}, timeout=timeout)
        if resp.status_code == 200:
            return resp.text.strip()
    except requests.RequestException:
        return None
    return None

def get_ip_info(ip, timeout=6):
    """
    Ambil info IP (opsional) — menggunakan ip-api.com (public, rate-limited).
    Jika tidak ingin dependency ke layanan luar, panggilan ini bisa dilewati.
    """
    if not ip:
        return None
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=timeout)
        if resp.status_code == 200:
            d = resp.json()
            if d.get("status") == "success":
                return d
    except requests.RequestException:
        return None
    return None

# -------------------- Local redirect logger (Flask example) --------------------

FLASK_TEMPLATE = r'''
# Save this as run_redirect_server.py and run on your own server/host:
#
# WARNING:
# - This server logs incoming requests to a local file.
# - Use this only on servers you control and only for users who provided consent.
# - To reduce privacy risks, enable "hash_ip" mode to store hashed IPs instead of raw IPs.
#
# Dependencies: pip install Flask requests
#
from flask import Flask, request, redirect, abort
import hashlib, json, time, os

app = Flask(__name__)

# Path to log file (on server)
LOG_PATH = "redirect_log.jsonl"

# The target URL to redirect visitors to (for example, the actual youtube link)
TARGET_URL = "{target_url}"

# If True, store hashed IP (sha256 of ip + salt) instead of raw IP
HASH_IP = {hash_ip}

# Salt for hashing (keep secret)
HASH_SALT = "{hash_salt}"

def hash_ip(ip):
    if not ip:
        return None
    s = (ip + HASH_SALT).encode("utf-8")
    return hashlib.sha256(s).hexdigest()

def log_visit(entry):
    # Append JSON-lines for easy processing
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\\n")

@app.route("/", defaults={{}})
@app.route("/<path:path>")
def handle(path=""):
    # Extract IP (note: if behind reverse proxy, use X-Forwarded-For only if you trust proxy)
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")
    ts = time.time()
    if HASH_IP:
        stored_ip = hash_ip(ip)
    else:
        stored_ip = ip
    entry = {{
        "ts": ts,
        "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "path": "/" + path,
        "ip": stored_ip,
        "user_agent": ua
    }}
    log_visit(entry)
    # Redirect to the target (HTTP 302)
    return redirect(TARGET_URL, code=302)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port={port})
'''

def create_redirect_server_file(target_url, out_path="run_redirect_server.py",
                                port=8080, hash_ip=True, salt=None):
    """
    Buat file Flask yang menjalankan redirect server untuk target_url.
    *Hanya* buat file; jangan jalankan demi privasi pihak lain.
    """
    if salt is None:
        # generate simple salt
        salt = hashlib.sha256(os.urandom(16)).hexdigest()
    contents = FLASK_TEMPLATE.format(
        target_url=target_url,
        hash_ip=str(bool(hash_ip)),
        hash_salt=salt,
        port=int(port)
    )
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(contents)
    return out_path, salt

# -------------------- Utilities --------------------

def hash_ip_local(ip, salt):
    if ip is None:
        return None
    return hashlib.sha256((ip + salt).encode("utf-8")).hexdigest()

# -------------------- Submenu --------------------

from rich.panel import Panel
from rich.text import Text

def menu_youtube():
    while True:
        banner()
        
        menu_text = Text()
        menu_text.append("📌 Pilih aksi:\n\n", style="bold")
        menu_text.append("1. Parse & validasi YouTube link\n", style="cyan")
        menu_text.append("2. Ambil metadata video via YouTube Data API (butuh API key milikmu)\n", style="cyan")
        menu_text.append("3. Buat contoh local redirect server (file .py) untuk LOG kunjungan (HANYA servermu)\n", style="cyan")
        menu_text.append("4. Exit Atau Keluar Program", style="cyan")
        
        console.print(
            Panel(menu_text, title="[bold blue]YouTube - Link Helper[/bold blue]", box=box.ROUNDED, border_style="blue")
        )
        
        choice = Prompt.ask(" YouTube_Helper >", default="1")

        if choice == "1":
            url = Prompt.ask(" Masukkan YouTube URL / teks")
            vid = display_link_info(url)
            if vid:
                if Confirm.ask("🔎 Ambil metadata via YouTube Data API sekarang? (kamu butuh API key)", default=False):
                    key = Prompt.ask(" Masukkan API key YouTube (atau kosongkan untuk batal)", password=True)
                    if key.strip():
                        item = get_youtube_video_metadata(key.strip(), vid)
                        show_video_metadata(item)
            console.input("\n[bold cyan] Tekan Enter untuk kembali ke submenu...[/bold cyan]")

        elif choice == "2":
            key = Prompt.ask(" Masukkan API key YouTube (atau kosongkan untuk batal)", password=True)
            if not key.strip():
                console.print("[yellow] Dibatalkan.[/yellow]")
                console.input("\n[bold cyan] Tekan Enter untuk kembali...[/bold cyan]")
                continue
            url = Prompt.ask(" Masukkan YouTube URL / video ID")
            vid = extract_video_id(url) or (url if re.match(r'^[A-Za-z0-9_\-]{11}$', url) else None)
            if not vid:
                console.print("[red] Tidak dapat mengekstrak video ID dari input.[/red]")
            else:
                item = get_youtube_video_metadata(key.strip(), vid)
                show_video_metadata(item)
            console.input("\n[bold cyan] Tekan Enter untuk kembali ke submenu...[/bold cyan]")

        elif choice == "3":
            console.print("\n[bold red]PENTING:[/bold red] File yang akan dibuat dapat mencatat IP visitor. "
                          "Gunakan hanya pada server yang kamu kendalikan dan hanya untuk visitor yang memberi izin.")
            if not Confirm.ask("Saya mengerti & akan menggunakan file ini hanya pada server yang saya kendalikan dan dengan izin (Ya/Tidak)", default=False):
                console.print("[yellow]Dibatalkan — tidak membuat file.[/yellow]")
                console.input("\n[bold cyan]Tekan Enter untuk kembali...[/bold cyan]")
                continue

            target = Prompt.ask(" Masukkan TARGET URL tujuan redirect (mis: https://www.youtube.com/watch?v=... )")
            outpath = Prompt.ask(" Masukkan nama file output untuk server Flask", default="run_redirect_server.py")
            port = Prompt.ask(" Port yang akan digunakan oleh server Flask", default="8080")
            hash_choice = Confirm.ask(" Simpan IP sebagai HASHED value (lebih aman) ? (jangan simpan raw IP jika tidak perlu)", default=True)
            salt = None
            if hash_choice:
                salt = hashlib.sha256(os.urandom(16)).hexdigest()
                console.print(f"[green] Dihasilkan salt lokal (simpan ini dengan aman jika ingin de-hash):[/green] {salt[:16]}...[dim](disimpan ke file server yang dibuat)[/dim]")

            try:
                created_path, used_salt = create_redirect_server_file(
                    target_url=target,
                    out_path=outpath,
                    port=int(port),
                    hash_ip=hash_choice,
                    salt=salt
                )
                console.print(f"[green]File server redirect dibuat: {created_path}[/green]")
                console.print("[cyan]Instruksi singkat:[/cyan]")
                console.print("- Jalankan file tersebut pada server yang kamu kontrol: python run_redirect_server.py")
                console.print("- Pastikan domain/port dapat diakses oleh target audience dan bahwa kamu memiliki izin untuk mencatat kunjungan.")
                console.print("- Log tersimpan ke redirect_log.jsonl (JSON lines).")
                console.print("- Untuk privasi yang lebih baik, gunakan HASH mode (default di atas).")
            except Exception as e:
                console.print(f"[red]Gagal membuat file server: {e}[/red]")

            console.input("\n[bold cyan]Tekan Enter untuk kembali ke submenu...[/bold cyan]")

        else:  # 4
            break

if __name__ == "__main__":
    menu_youtube()
