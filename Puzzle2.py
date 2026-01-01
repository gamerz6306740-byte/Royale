import json
import hashlib
import asyncio
import httpx
import time
import base64
import os
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from aiohttp import web

# ================= UPDATED CASH PANDA CONFIG (cash-panda-76893) =================
JSON_URL = "https://gist.githubusercontent.com/gamerz6306740-byte/ce8d2837b315b80392fba7fe791150a3/raw/06595419a9886fd2a08279bb910c3e6ee974e3a5/Anccgaj.json"
FIREBASE_KEY = "AIzaSyAMQu13Wg_7UnuwSstH6JKfh37VIEZ4bGg"
PROJECT_ID = "cash-panda-76893"
REFRESH_TOKEN = "AMf-vBzRDoETXA6y7BD0CfoeA-XvzeSBgNvXKDYSAjIO8UP0dpYxzfzLZkVIbejjel0ciaUSHyywuGU4-d9uCwWfGs2gLCNSetxlOtZY3HrNZwKZXvjpgMU8MTGedxCI7Dwt0dJdDBqBwxjvxZAkVI9RmGg9hmt7eP4tYmpoyd1ujIYbGlH9xqXv8GCLozBEOgOicI6BJ-nl_qEYH5PUsCudn0cj5_LXzSaYed6XPGb3LhA2Pa2vxr16ZDxvSestxB2qbQm3ignTSElW_5AtR0-x3RUo913ameRfgQwC4I0porPjpQsJULjrly67GFJsjzvrZd8CbEXXh9BLE6AQzRhgRvAR1db2CWJjIME6F8SIMR-zmnuNKgvZgS_V8cZrlTj_OlKmHjBe3gc8F2KXVSnKFauB46_Xf3WigQ7ryTMlHTZ2hVNOCq8"
SPOT_ID = "2759528"

BASE_URL = "https://fairbid.inner-active.mobi/simpleM2M/fyberMediation"
SALT = "j8n5HxYA0ZVF"
ENCRYPTION_KEY = "6fbJwIfT6ibAkZo1VVKlKVl8M2Vb7GSs"
PORT = int(os.getenv("PORT", 10000)) 

# ---------------- INTERNAL GLOBALS ---------------- #
_last_ts = 0
_stats = {"start_time": time.time(), "boosts_count": 0, "status": "Initializing"}

def log(msg: str):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [BOT] {msg}", flush=True)

# ---------------- CRYPTO & HASHING ---------------- #
def build_hash_payload(user_id, url):
    global _last_ts
    now = max(int(time.time()), _last_ts + 1)
    _last_ts = now
    ts_str = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    raw = f"{url}{ts_str}{SALT}"
    return json.dumps({
        "user_id": user_id,
        "timestamp": now,
        "hash_value": hashlib.sha512(raw.encode()).hexdigest(),
    }, separators=(",", ":"))

def encrypt_offer_data(offer_id):
    key = hashlib.sha256(ENCRYPTION_KEY.encode()).digest()
    raw = json.dumps({"offerId": offer_id}, separators=(",", ":")).encode()
    cipher = AES.new(key, AES.MODE_ECB)
    return {"data": {"data": base64.b64encode(cipher.encrypt(pad(raw, 16))).decode()}}

# ---------------- TOKEN MANAGER ---------------- #
class TokenManager:
    def __init__(self):
        self.token, self.uid, self.expiry = None, None, 0

    async def get(self, client):
        if not self.token or time.time() >= self.expiry:
            r = await client.post(f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_KEY}",
                data={"grant_type": "refresh_token", "refresh_token": REFRESH_TOKEN})
            r.raise_for_status()
            j = r.json()
            self.token, self.uid = j["id_token"], j["user_id"]
            self.expiry = time.time() + int(j["expires_in"]) - 60
            log(f"🔑 Auth Refreshed: {self.uid}")
        return self.token, self.uid

# ---------------- BOOST LOGIC ---------------- #
async def run_boost(client, user_id, payload_str):
    try:
        r = await client.post(f"{BASE_URL}?spotId={SPOT_ID}", content=payload_str)
        text = r.text
        if '"completion":"' in text:
            comp_url = text.split('"completion":"')[1].split('"')[0]
            # Ping Impression
            if '"impression":"' in text:
                imp_url = text.split('"impression":"')[1].split('"')[0]
                await client.get(imp_url)
            # Ping Completion with Hash
            await client.post(comp_url, content=build_hash_payload(user_id, comp_url))
            _stats["boosts_count"] += 1
            return True
    except: pass
    return False

# ---------------- BOT LOOP ---------------- #
async def bot_loop():
    _stats["status"] = "Running"
    async with httpx.AsyncClient(http2=True, timeout=30, verify=False) as client:
        # Load Config with Retry
        cfg_data = None
        while not cfg_data:
            try:
                resp = await client.get(JSON_URL)
                cfg_data = resp.json()
                log("📡 Configuration loaded successfully")
            except:
                log("⚠️ Config load failed, retrying in 10s...")
                await asyncio.sleep(10)
        
        user_id = cfg_data["client_params"]["publisher_supplied_user_id"]
        payload_str = json.dumps(cfg_data, separators=(",", ":"))
        tm = TokenManager()

        while True:
            try:
                token, uid = await tm.get(client)
                
                # Check Firestore for offers
                q_url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}:runQuery"
                r = await client.post(q_url, headers={"Authorization": f"Bearer {token}"},
                    json={"structuredQuery": {"from": [{"collectionId": "superOffers"}],
                          "where": {"fieldFilter": {"field": {"fieldPath": "status"}, "op": "NOT_EQUAL", "value": {"stringValue": "COMPLETED"}}},
                          "limit": 1}})
                
                res = r.json()
                if not res or "document" not in res[0]:
                    _stats["status"] = "Waiting for offers"
                    await asyncio.sleep(60)
                    continue

                f = res[0]["document"]["fields"]
                offer_id = f["offerId"]["stringValue"]
                fees = int(f.get("fees", {}).get("integerValue", 0))
                log(f"🎯 Target Offer: {offer_id} | Need {fees} Boosts")

                # Boost Farming
                _stats["status"] = f"Farming {offer_id}"
                for i in range(fees + 1):
                    await run_boost(client, user_id, payload_str)
                    if i % 5 == 0: log(f"📤 Boost Progress: {i}/{fees}")
                    await asyncio.sleep(0.5)

                # Unlock & Claim
                _stats["status"] = f"Claiming {offer_id}"
                for action in ["superOffer_unlock", "superOffer_claim"]:
                    await client.post(f"https://us-central1-{PROJECT_ID}.cloudfunctions.net/{action}",
                        headers={"Authorization": f"Bearer {token}"}, json=encrypt_offer_data(offer_id))
                
                log(f"💰 Success! {offer_id} claimed.")
                await asyncio.sleep(30)

            except Exception as e:
                log(f"⚠️ Loop Error: {e}")
                await asyncio.sleep(20)

# ---------------- RENDER WEB SERVER ---------------- #
async def health_check(request):
    uptime = int(time.time() - _stats["start_time"])
    return web.json_response({
        "bot_status": _stats["status"],
        "uptime": f"{uptime//3600}h {(uptime%3600)//60}m",
        "boosts_farmed": _stats["boosts_count"]
    })

async def main():
    # START SERVER FIRST
    app = web.Application()
    app.router.add_get("/", health_check)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()
    log(f"📡 Render Health server live on port {PORT}")
    
    # RUN BOT
    await bot_loop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
