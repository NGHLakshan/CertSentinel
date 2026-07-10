import certstream
import asyncio
import json
import csv
import threading
import logging
import smtplib
import os
from datetime import datetime
from urllib.parse import urlparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
import socket
import geoip2.database
import requests
from dotenv import load_dotenv
import uvicorn
from ml_engine import risk_engine

# Key.env ෆයිල් එකෙන් credentials load කරනවා
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', 'Key.env'))

ALERT_EMAIL    = os.getenv("ALERT_EMAIL")
ALERT_PASSWORD = os.getenv("ALERT_PASSWORD")
TO_EMAIL       = os.getenv("TO_EMAIL")

LOG_FILE = os.path.join(os.path.dirname(__file__), 'suspicious_domains.log')

# Log file setup
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# FastAPI app
app = FastAPI(title="CertSentinel")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connected WebSocket clients
clients: list[WebSocket] = []

# Statistics
stats = {"total_scanned": 0, "total_suspicious": 0}

# Email alert (first detection only)
email_sent = False

# asyncio event loop (shared between threads)
loop: asyncio.AbstractEventLoop = None


# ─── WebSocket endpoint ───────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.append(ws)
    print(f"🔌 Client connected. Total: {len(clients)}")
    try:
        # Initial stats
        await ws.send_text(json.dumps({"type": "stats", **stats}))
        while True:
            await ws.receive_text()   # keep alive
    except WebSocketDisconnect:
        clients.remove(ws)
        print(f"🔌 Client disconnected. Total: {len(clients)}")


async def broadcast(data: dict):
    """Send JSON to all connected WebSocket clients."""
    dead = []
    for ws in clients:
        try:
            await ws.send_text(json.dumps(data))
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in clients:
            clients.remove(ws)


# ─── Manual Link Scanner API ─────────────────────────────────────────────────
@app.post("/api/scan-link")
async def scan_link(payload: dict = Body(...)):
    """Scan a user-provided URL and return AI risk analysis."""
    url = payload.get("url", "").strip()

    if not url:
        return {"error": "URL එකක් දෙන්න."}

    # Add scheme if missing so urlparse works
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        return {"error": "Invalid URL format."}

    if not domain:
        return {"error": "Domain එකක් හොයාගන්න බැරි උනා."}

    # Remove port if present
    domain = domain.split(":")[0]

    # ML risk scoring
    from ml_engine import extract_features
    risk_score = risk_engine.predict_risk(domain)
    features = extract_features(domain)

    # Keyword matching
    matched_keywords = [w for w in SUSPICIOUS_WORDS if w in domain.lower()]

    # Verdict
    if risk_score >= 70:
        verdict = "HIGH RISK 🔴"
    elif risk_score >= 40:
        verdict = "MEDIUM RISK 🟡"
    else:
        verdict = "SAFE 🟢"

    try:
        csv_file = os.path.join(os.path.dirname(__file__), 'manual_scans.csv')
        file_exists = os.path.isfile(csv_file)
        with open(csv_file, 'a', newline='', encoding='utf-8') as cb:
            writer = csv.writer(cb)
            if not file_exists:
                writer.writerow(["Timestamp", "Domain", "Original_URL", "Risk_Score", "Verdict", "Matched_Keywords", "Features"])
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            writer.writerow([
                timestamp,
                domain,
                url,
                risk_score,
                verdict,
                ",".join(matched_keywords) if matched_keywords else "None",
                json.dumps(features)
            ])
    except Exception as e:
        print(f"⚠️ Failed to save scan result to CSV: {e}")

    return {
        "domain": domain,
        "original_url": url,
        "risk_score": risk_score,
        "verdict": verdict,
        "matched_keywords": matched_keywords,
        "features": features,
    }



# ─── Historical Analytics API ────────────────────────────────────────────────
@app.get("/api/analytics")
async def get_analytics(view: str = "daily"):
    """Return daily or weekly aggregated threat counts from the stored CSV."""
    csv_file = os.path.join(os.path.dirname(__file__), 'live_suspicious_domains.csv')
    counts: dict = {}

    if os.path.isfile(csv_file):
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ts_str = row.get("Timestamp", "").strip()
                    if not ts_str:
                        continue
                    try:
                        dt = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        continue

                    if view == "weekly":
                        # ISO week label: "2025-W28"
                        label = f"{dt.isocalendar()[0]}-W{dt.isocalendar()[1]:02d}"
                    else:
                        # Daily label: "2025-07-10"
                        label = dt.strftime('%Y-%m-%d')

                    counts[label] = counts.get(label, 0) + 1
        except Exception as e:
            print(f"⚠️ Analytics read error: {e}")

    # Sort labels chronologically and limit window
    sorted_labels = sorted(counts.keys())
    limit = 8 if view == "weekly" else 7
    sorted_labels = sorted_labels[-limit:]

    result = [{"label": lbl, "count": counts[lbl]} for lbl in sorted_labels]
    return {"view": view, "data": result}


# ─── GeoIP Location ──────────────────────────────────────────────────────────
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), 'GeoLite2-City.mmdb')
GEOIP_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
geoip_reader = None

def get_location_info(domain: str) -> dict:
    import random
    try:
        actual_domain = domain.replace("fake-", "")
        ip = socket.gethostbyname(actual_domain)
        if geoip_reader:
            response = geoip_reader.city(ip)
            return {
                "country": response.country.iso_code or "Unknown",
                "lat": response.location.latitude or 0.0,
                "lon": response.location.longitude or 0.0,
                "ip": ip
            }
        return {"country": "Unknown", "lat": 0.0, "lon": 0.0, "ip": ip}
    except Exception:
        if "fake-" in domain:
            return {"country": "XX", "lat": random.uniform(-60.0, 60.0), "lon": random.uniform(-140.0, 140.0), "ip": "127.0.0.1"}
        return {"country": "Unknown", "lat": 0.0, "lon": 0.0, "ip": "Unknown"}

# ─── CSV Database Storage ────────────────────────────────────────────────────
def save_suspicious_domain_to_csv(domain: str, timestamp: str, keyword: str, tld: str, risk_score: float, country: str, lat: float, lon: float):
    """Auto-saves suspicious domain data to a CSV file acting as a database."""
    csv_file = os.path.join(os.path.dirname(__file__), 'live_suspicious_domains.csv')
    file_exists = os.path.isfile(csv_file)
    try:
        with open(csv_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Timestamp", "Domain", "Keyword", "TLD", "Risk_Score", "Country", "Lat", "Lon"])
            writer.writerow([timestamp, domain, keyword, tld, risk_score, country, lat, lon])
    except Exception as e:
        print(f"⚠️ Failed to save to CSV database: {e}")

# ─── Email alert ─────────────────────────────────────────────────────────────
def send_email_alert(domain: str):
    global email_sent
    if email_sent or not ALERT_EMAIL or not ALERT_PASSWORD:
        return
    try:
        msg = MIMEMultipart()
        msg['From']    = ALERT_EMAIL
        msg['To']      = TO_EMAIL
        msg['Subject'] = "🚨 StreamAnalytics: Suspicious Domain Detected!"
        msg.attach(MIMEText(
            f"Domain  : {domain}\n"
            f"Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Log File: {LOG_FILE}\n\n-- StreamAnalytics Hunter",
            'plain'
        ))
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(ALERT_EMAIL, ALERT_PASSWORD)
            server.sendmail(ALERT_EMAIL, TO_EMAIL, msg.as_string())
        print(f"📧 [Email Alert Sent] -> {TO_EMAIL}")
        email_sent = True
    except Exception as e:
        print(f"⚠️  Email error: {e}")


# ─── CertStream callback ──────────────────────────────────────────────────────
SUSPICIOUS_WORDS = ['login', 'bank', 'secure', 'account', 'paypal',
                    'support', 'update', 'verify']

def cert_callback(message, context):
    global stats

    if message['message_type'] == "heartbeat":
        print("💓 [Heartbeat Received]")
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            stats["total_scanned"] += 1

            # Push live scanning numbers every 50 items so the dashboard counters update
            if stats["total_scanned"] % 50 == 0:
                stats_payload = {"type": "stats", "total_scanned": stats["total_scanned"], "total_suspicious": stats["total_suspicious"]}
                if loop and not loop.is_closed():
                    asyncio.run_coroutine_threadsafe(broadcast(stats_payload), loop)

            if any(word in domain for word in SUSPICIOUS_WORDS):
                stats["total_suspicious"] += 1
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                print(f"🚨 [සැකකටයුතු!] -> {domain}")

                # 1. Log file
                logging.info(f"SUSPICIOUS: {domain}")

                # 2. Email (first hit)
                threading.Thread(target=send_email_alert, args=(domain,), daemon=True).start()

                # 3. Push to all WebSocket clients
                matched_kw = next((w for w in SUSPICIOUS_WORDS if w in domain), "other")
                tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else "unknown"
                risk_score = risk_engine.predict_risk(domain)
                
                loc = get_location_info(domain)
                
                # 4. Save to CSV Database
                save_suspicious_domain_to_csv(domain, timestamp, matched_kw, tld, risk_score, loc['country'], loc['lat'], loc['lon'])
                
                payload = {
                    "type": "alert",
                    "domain": domain,
                    "timestamp": timestamp,
                    "keyword": matched_kw,
                    "tld": tld,
                    "risk_score": risk_score,
                    "country": loc['country'],
                    "lat": loc['lat'],
                    "lon": loc['lon'],
                    "ip": loc['ip'],
                    "total_scanned": stats["total_scanned"],
                    "total_suspicious": stats["total_suspicious"],
                }
                if loop and not loop.is_closed():
                    asyncio.run_coroutine_threadsafe(broadcast(payload), loop)


def start_certstream():
    print("සජීවී දත්ත ප්‍රවාහයට සම්බන්ධ වෙමින් පවතී...")
    print("සැකකටයුතු වෙබ්අඩවි සෙවීම ආරම්භ කළා...\n")
    certstream.listen_for_events(cert_callback, url='wss://certstream.calidog.io/')


# ─── Startup / Main ──────────────────────────────────────────────────────────

async def simulated_stream():
    """Fallback Simulator since CertStream API is currently unstable/offline"""
    import random
    words = ['login', 'bank', 'secure', 'account', 'paypal', 'support', 'update', 'verify', 'auth', 'web']
    tlds = ['.com', '.net', '.org', '.io', '.xyx']
    
    while True:
        await asyncio.sleep(random.uniform(0.05, 0.2))  # simulate high traffic
        stats["total_scanned"] += 1
        
        # Periodically update the stats counter on UI
        if stats["total_scanned"] % 50 == 0:
            await broadcast({"type": "stats", "total_scanned": stats["total_scanned"], "total_suspicious": stats["total_suspicious"]})
            
        # 1-in-300 chance to hit a "phishing" domain
        if random.randint(1, 300) == 1:
            stats["total_suspicious"] += 1
            domain = f"{random.choice(words)}-{random.choice(words)}{random.choice(tlds)}"
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            kw = next((w for w in words if w in domain), words[0])
            tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ".com"
            risk_score = risk_engine.predict_risk(f"fake-{domain}")
            
            loc = get_location_info(f"fake-{domain}")
            
            # Save to CSV Database
            save_suspicious_domain_to_csv(f"fake-{domain}", timestamp, kw, tld, risk_score, loc['country'], loc['lat'], loc['lon'])
            
            payload = {
                "type": "alert", "domain": f"fake-{domain}", "timestamp": timestamp,
                "keyword": kw, "tld": tld, "risk_score": risk_score,
                "country": loc['country'], "lat": loc['lat'], "lon": loc['lon'], "ip": loc['ip'],
                "total_scanned": stats["total_scanned"], "total_suspicious": stats["total_suspicious"],
            }
            logging.info(f"SUSPICIOUS (SIMULATED): fake-{domain}")
            await broadcast(payload)

@app.on_event("startup")
async def startup_event():
    global loop, geoip_reader
    loop = asyncio.get_event_loop()
    
    # Download GeoIP DB if not exist
    if not os.path.exists(GEOIP_DB_PATH):
        print("🌍 Downloading GeoLite2-City database (~30MB)...")
        try:
            r = requests.get(GEOIP_DB_URL, stream=True)
            with open(GEOIP_DB_PATH, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            print("✅ GeoLite2-City database downloaded.")
        except Exception as e:
            print(f"⚠️ Failed to download GeoIP DB: {e}")
            
    if os.path.exists(GEOIP_DB_PATH):
        try:
            geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except Exception as e:
            print(f"⚠️ Error loading GeoIP DB: {e}")
    
    # Start actual CertStream just in case it comes online
    t = threading.Thread(target=start_certstream, daemon=True)
    t.start()
    
    # Start Simulator because CertStream is currently dead globally
    asyncio.create_task(simulated_stream())
    
    print("🌐 WebSocket API ready: ws://localhost:8000/ws")
    print("⚠️  [NOTICE] CertStream feed seems offline. Running SIMULATOR mode alongside.")


if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
