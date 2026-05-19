import re
import socket
import logging
from datetime import datetime

from scapy.all import sniff, UDP, IP, Raw

# -----------------------------
# LOGGING
# -----------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    handlers=[
        logging.FileHandler("anydesk_inventory.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# -----------------------------
# REGEX
# -----------------------------

ANYDESK_ID_RE = re.compile(r"\b\d{7,10}\b")

# -----------------------------
# CACHE
# -----------------------------

seen = {}

# -----------------------------
# HOSTNAME RESOLUTION
# -----------------------------

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "unknown"

# -----------------------------
# PACKET HANDLER
# -----------------------------

def handle_packet(pkt):

    if not pkt.haslayer(UDP):
        return

    if not pkt.haslayer(Raw):
        return

    try:
        payload = bytes(pkt[Raw]).decode(errors="ignore")
    except Exception:
        return

    ids = ANYDESK_ID_RE.findall(payload)

    if not ids:
        return

    ip = pkt[IP].src
    hostname = resolve_hostname(ip)

    for ad_id in ids:

        cache_key = f"{ad_id}_{ip}"

        if cache_key in seen:
            continue

        seen[cache_key] = datetime.utcnow()

        logging.info(
            f"AnyDeskID={ad_id} "
            f"IP={ip} "
            f"HOST={hostname}"
        )

# -----------------------------
# START
# -----------------------------

print("Listening for AnyDesk LAN discovery packets...")

sniff(
    filter="udp",
    prn=handle_packet,
    store=False
)
