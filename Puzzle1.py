# save as: royal_bot_termux.py
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

# ================= HARDCODED CONFIG =================

JSON_URL = "https://gist.githubusercontent.com/gamerz6306740-byte/09dd8594f3f7e99dcde38c87ca22e47d/raw/85fbd7216e5446ac550bcc7ee9bc40a912b8c8b3/Vdvdbz.json"
FIREBASE_KEY = "AIzaSyCF-M9WFi6IsTIn7G3hzG_nIi3rWA3XD6o"
PROJECT_ID = "puzzle-master-51426"

REFRESH_TOKEN = "AMf-vBzX2WqnWSbOuvbvbNsOVuCTKfNK4RZKq6zF14Y-iCr0MHCMjAj1U37jGGACiaBxUh1OQtgmiA8T-QmJLuV-oIRqkN7tgz24qs0w50783Fgj0U-Qd7BFuVbYV8pm6xZE6YCKoLVl88Gg20pVmBQyz5K4pHNMIBnwcz1JdO5CSBWpOIG8FuSvfdc78n3XkAEqhR3aeLHtQvynZJmECDitJCHoVhuQAHHnHLsYXoKlHI0F6iYxCt9w4idVYI7kH_6EmV1njyp8HPnKnifOQRfzXjZ-LkHh5mTocxhliUz-IHVccbkY3dxOIMFmWuOGK-BxNq0fGL4jvzyP0qheYVSuwtu0NHRRlfmsncDTH60fI6gsAWlh9xXS1ZQhZ6JKAlGulZGOymlXj9Ppet5QXIR8WWF0R5SUcfNd5L5JsKJW0HKkcf_ovRA"

BASE_URL = "https://fairbid.inner-active.mobi/simpleM2M/fyberMediation"
SPOT_ID = "2052855"
SALT = "j8n5HxYA0ZVF"

ENCRYPTION_KEY = "6fbJwIfT6ibAkZo1VVKlKVl8M2Vb7GSs"

REQUEST_TIMEOUT = 30

# ====================================================

_last_timestamp = 0
_processed_offers = set()
_stats = {
    "start_time": time.time(),
    "status": "running"
}

# ---------------- LOG ---------------- #

def log(msg: str):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {msg}", flush=True)

# ---------------- CLIENT ---------------- #

async def create_client():
    return httpx.AsyncClient(
        http2=True,
        headers={
            "User-Agent": "Mozilla/5.0 (Android)",
            "Accept": "application/json",
        },
        timeout=httpx.Timeout(REQUEST_TIMEOUT),
        # ⚠️ Removed verify=False for security (Termux handles certs fine)
    )

# ---------------- LOAD CONFIG FROM URL ---------------- #

async def load_config(client):
    log("[CONFIG] Fetching JSON data from URL...")
    try:
        r = await client.get(JSON_URL)
        r.raise_for_status()
        data = r.json()
        
        user_id = data["client_params"]["publisher_supplied_user_id"]
        log(f"[CONFIG] Loaded config for user: {user_id}")
        
        return {
            "user_id": user_id,
            "payload": json.dumps(data, separators=(",", ":")),
        }
    except Exception as e:
        log(f"[CONFIG] Failed to load config: {e}")
        raise

# ---------------- AUTH ---------------- #

async def get_id_token(client):
    r = await client.post(
        f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_KEY}",  # 🔧 Fixed space issue
        data={
            "grant_type": "refresh_token",
            "refresh_token": REFRESH_TOKEN
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    r.raise_for_status()
    j = r.json()
    return j["id_token"], j["user_id"], int(j["expires_in"])

class TokenManager:
    def __init__(self):
        self.token = None
        self.uid = None
        self.expiry = 0

    async def get(self, client):
        if not self.token or time.time() >= self.expiry:
            self.token, self.uid, ttl = await get_id_token(client)
            self.expiry = time.time() + ttl - 30
            log(f"[AUTH] Token refreshed (valid ~{ttl//60} min)")
        return self.token, self.uid

# ---------------- HASH (FAIRBID) ---------------- #

def build_hash_payload(user_id, url):
    global _last_timestamp

    now = int(time.time())
    if now <= _last_timestamp:
        now = _last_timestamp + 1
    _last_timestamp = now

    ts = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    raw = f"{url}{ts}{SALT}"

    return json.dumps(
        {
            "user_id": user_id,
            "timestamp": now,
            "hash_value": hashlib.sha512(raw.encode()).hexdigest(),
        },
        separators=(",", ":"),
    )

# ---------------- ENCRYPTION ---------------- #

def encrypt_offer(offer_id):
    key = hashlib.sha256(ENCRYPTION_KEY.encode()).digest()
    raw = json.dumps({"offerId": offer_id}, separators=(",", ":")).encode()
    cipher = AES.new(key, AES.MODE_ECB)
    enc = cipher.encrypt(pad(raw, AES.block_size))
    return {"data": {"data": base64.b64encode(enc).decode()}}

# ---------------- FIRESTORE ---------------- #

async def get_super_offer(client, token, uid):
    try:
        r = await client.post(
            f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}:runQuery",  # 🔧 Fixed space
            headers={"Authorization": f"Bearer {token}"},
            json={
                "structuredQuery": {
                    "from": [{"collectionId": "superOffers"}],
                    "where": {
                        "fieldFilter": {
                            "field": {"fieldPath": "status"},
                            "op": "NOT_EQUAL",
                            "value": {"stringValue": "COMPLETED"}
                        }
                    },
                    "limit": 1
                }
            }
        )
        r.raise_for_status()
        for item in r.json():
            doc = item.get("document")
            if not doc:
                continue

            f = doc["fields"]
            offer_id = f["offerId"]["stringValue"]

            if offer_id in _processed_offers:
                return None

            return {
                "offerId": offer_id,
                "reward": int(f.get("rewardAmount", {}).get("integerValue", 0)),
                "fees": int(f.get("fees", {}).get("integerValue", 0)),
            }
    except Exception as e:
        log(f"[FIRESTORE] Error getting offer: {e}")
    
    return None

async def get_boosts(client, token, uid):
    try:
        r = await client.get(
            f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/users/{uid}?mask.fieldPaths=boosts",  # 🔧 Fixed space
            headers={"Authorization": f"Bearer {token}"}
        )
        if r.status_code != 200:
            return 0

        return int(
            r.json()
            .get("fields", {})
            .get("boosts", {})
            .get("integerValue", 0)
        )
    except Exception:
        return 0

# ---------------- FAIRBID (SILENT) ---------------- #

async def run_fairbid(client, cfg):
    try:
        r = await client.post(f"{BASE_URL}?spotId={SPOT_ID}", content=cfg["payload"])
        if r.status_code >= 400:
            log(f"[FAIRBID] Failed request: {r.status_code}")
            return

        text = r.text
        
        # Parse impression URL
        try:
            if "impression" in text and 'impression":"' in text:
                parts = text.split('impression":"')
                if len(parts) > 1:
                    impression_url = parts[1].split('"')[0]
                    if impression_url.startswith('http'):
                        await client.get(impression_url)
        except Exception as e:
            log(f"[IMPRESSION] Error: {e}")
        
        # Parse completion URL
        try:
            if "completion" in text and 'completion":"' in text:
                parts = text.split('completion":"')
                if len(parts) > 1:
                    comp = parts[1].split('"')[0]
                    if comp.startswith('http'):
                        await client.post(comp, content=build_hash_payload(cfg["user_id"], comp))
        except Exception as e:
            log(f"[COMPLETION] Error: {e}")
            
    except Exception as e:
        log(f"[FAIRBID] Exception: {e}")

# ---------------- UNLOCK / CLAIM ---------------- #

async def call_fn(client, token, name, offer_id):
    try:
        r = await client.post(
            f"https://us-central1-{PROJECT_ID}.cloudfunctions.net/{name}",
            headers={"Authorization": f"Bearer {token}"},
            json=encrypt_offer(offer_id)
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        log(f"[FN CALL] Error in {name}: {e}")
        return {}

async def unlock_and_claim(client, token, offer):
    unlock = await call_fn(client, token, "superOffer_unlock", offer["offerId"])
    if unlock.get("result", {}).get("status") != "SUCCESS":
        log(f"[UNLOCK] Failed: {unlock}")
        return False

    claim = await call_fn(client, token, "superOffer_claim", offer["offerId"])
    success = claim.get("result", {}).get("status") == "SUCCESS"
    if not success:
        log(f"[CLAIM] Failed: {claim}")
    return success

# ---------------- MAIN LOOP ---------------- #

async def bot_loop():
    """Main bot logic — Termux-friendly (no web server)"""
    client = await create_client()
    
    try:
        cfg = await load_config(client)
        tm = TokenManager()

        log("[BOT] 🚀 Starting Royal Cash Bot (Termux Edition)")
        log(f"[BOT] User ID: {cfg['user_id']}")
        log("=" * 60)

        while True:
            try:
                token, uid = await tm.get(client)

                offer = await get_super_offer(client, token, uid)
                if not offer:
                    await asyncio.sleep(5)
                    continue

                log(f"[OFFER] 🔍 Found offer {offer['offerId']} | Reward: {offer['reward']} | Fees: {offer['fees']}")
                
                target = offer["fees"] + 1
                boosts = 0

                while boosts < target:
                    boosts = await get_boosts(client, token, uid)
                    if boosts >= target:
                        break
                    log(f"[BOOST] Current: {boosts} → Need: {target} → Running ad...")
                    await run_fairbid(client, cfg)
                    await asyncio.sleep(0.5)  # Slight delay to avoid hammering

                log(f"[BOOST] ✅ Reached {boosts} boosts. Unlocking offer...")

                if await unlock_and_claim(client, token, offer):
                    log(
                        f"✅ [CLAIMED] Offer: {offer['offerId']} "
                        f"| Reward: {offer['reward']} coins | Fees: {offer['fees']}"
                    )
                else:
                    log(f"❌ [FAILED] Could not claim offer {offer['offerId']}")

                _processed_offers.add(offer["offerId"])
                await asyncio.sleep(2)

            except KeyboardInterrupt:
                log("🛑 Bot stopped by user.")
                break
            except Exception as e:
                log(f"[ERROR] Bot loop error: {e}")
                await asyncio.sleep(10)

    except Exception as e:
        log(f"[FATAL] Bot initialization failed: {e}")
        raise
    finally:
        await client.aclose()
        log("[BOT] Client closed. Goodbye!")

# ---------------- ENTRY POINT ---------------- #

def main():
    log("=" * 60)
    log("📱 Royal Cash Bot — Termux Edition")
    log("📌 Press Ctrl+C to stop.")
    log("=" * 60)
    try:
        asyncio.run(bot_loop())
    except KeyboardInterrupt:
        print("\n👋 Bot exited cleanly.")

if __name__ == "__main__":
    main() 
