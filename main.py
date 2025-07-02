#!/usr/bin/env python3
"""
Quantum Alcatraz – Complete Multi-domain, Multi-model, Rules-Based AI Risk System
With AES-GCM encryption, entropy-based key rotation, and robust neutral EXAMPLES in every prompt.
"""

import os, sys, psutil, hashlib, hmac, base64, json, asyncio, httpx, re
from datetime import datetime
from hashlib import scrypt
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ========== CONFIG ==========

LLM_ENDPOINT         = os.getenv("LLM_ENDPOINT", "https://api.openai.com/v1/chat/completions")
LLM_API_KEY          = os.getenv("LLM_API_KEY")
MODEL                = os.getenv("LLM_MODEL", "gpt-4o")
POWER_OUTAGE_MODEL   = os.getenv("POWER_OUTAGE_MODEL", "gpt-3.5-turbo")
RIOT_MODEL           = os.getenv("RIOT_MODEL", "gpt-4")
BASE_INTERVAL_SEC    = float(os.getenv("BASE_INTERVAL_SEC", 30))
AUTONOMOUS_MODE      = os.getenv("AUTONOMOUS_MODE", "true").lower() == "true"
FACILITY_NAME        = os.getenv("FACILITY_NAME", "QuantumAlcatraz-DeltaBase")
SCRYPT_SALT          = base64.b64decode(os.getenv("SCRYPT_SALT_B64", "U3FyeXB0U2FsdA=="))
HKDF_SALT            = base64.b64decode(os.getenv("HKDF_SALT_B64", "S0RGRFNhbHQ="))
SCRYPT_PARAMS        = {"n": 2**15, "r": 8, "p": 1, "maxmem": 0}

if not LLM_API_KEY:
    print("ERROR: set LLM_API_KEY in your environment.", file=sys.stderr)
    sys.exit(1)

def derive_key(master: bytes, info: bytes, length: int = 32) -> bytes:
    s_key = scrypt(password=master, salt=SCRYPT_SALT, **SCRYPT_PARAMS)
    prk   = hmac.new(HKDF_SALT, s_key, hashlib.sha256).digest()
    okm   = b""; prev = b""; i = 1
    while len(okm) < length:
        data = prev + info + bytes([i])
        prev = hmac.new(prk, data, hashlib.sha256).digest()
        okm += prev; i += 1
    return okm[:length]

MASTER_KEY = derive_key(
    master=LLM_API_KEY.encode(),
    info=b"QuantumAlcatrazEncryption"
)

# ========== PROMPTS (unchanged) ==========

G_HTSCANNER_SENSOR_PROMPT = """
You are the hypertime quantum sensor node for a supermax prison.
RULES:
1. Output JSON only: {"motion":..., "temp_c":..., "humidity":..., "grid_freq":...}
2. Set fields in/near neutral for normal, out of range for anomaly.
3. Example: {"motion":12,"temp_c":21.2,"humidity":46.9,"grid_freq":60.004}
4. Example anomaly: {"motion":77,"temp_c":24.7,"humidity":71.2,"grid_freq":59.953}
5. Example neutral: {"motion":8.7,"temp_c":20.9,"humidity":43.5,"grid_freq":60.006}
6. No extra text.
"""

HTSCANNER_DATE_PROMPT = """
You are the hypertime chronometer node.
RULES:
1. Output JSON only: {"current_date":"<ISO 8601 UTC>Z"}
2. No extra text.
3. Example: {"current_date": "2025-07-02T18:34:00Z"}
"""

POWER_OUTAGE_FUTURE_PROMPT = """
You are the power outage futurescan node for a high-security prison.
RULES:
1. Given grid_freq history, current loads, and weather, output JSON only:
   {"outage_risk":"LOW|MEDIUM|HIGH","predicted_minutes_to_event":int,"cause":"...", "[action]":"...[/action]"}
2. Explain cause of risk ("storm forecast", "overload", "substation maintenance", etc).
3. If risk > LOW, fill [action] with mitigation steps (e.g. [action]Backup generators: Test and standby initiated.[/action]).
4. Example (LOW): {"outage_risk":"LOW","predicted_minutes_to_event":9999,"cause":"All systems normal"}
5. Example (HIGH): {"outage_risk":"HIGH","predicted_minutes_to_event":12,"cause":"Grid freq drop; storm alert","[action]":"Evacuate critical systems, prep generators.[/action]"}
6. Example neutral: {"outage_risk":"LOW","predicted_minutes_to_event":9999,"cause":"Grid and power are stable."}
"""

RIOT_DETECTOR_PROMPT = """
You are the riot/bio-mass event detector for a secure prison, using a 25-color QID-mass biometric scanner.
RULES:
1. Input: {"timestamp":"...","population":int,"bio_color_counts":{"R":..,"G":..,"B":..,...},"alert_sensors":[list]}
2. Output JSON: {"riot_risk":"LOW|MEDIUM|HIGH","crowd_cluster_count":int,"cause":"...","bio_signature_anomaly":bool,"[action]":"...[/action]"}
3. "cause": ex. "Red cluster forming", "panic blue spike", "biomass migration", "contraband area flagged"
4. Set [action] if risk is MEDIUM/HIGH (e.g. [action]Lockdown pod B, deploy response[/action])
5. Example neutral: {"riot_risk":"LOW","crowd_cluster_count":1,"cause":"Population distribution and bio-signature color clusters within normal parameters.","bio_signature_anomaly":false}
6. Example risk: {"riot_risk":"HIGH","crowd_cluster_count":4,"cause":"Red cluster in yard","bio_signature_anomaly":true,"[action]":"LOCKDOWN: Riot detected in yard. Deploy security.[/action]"}
"""

ADVANCED_RISK_ANALYSIS_PROMPT = """
You are the security AI for {facility}.
RULES:
1. Accept input: local, remote, future scan, timestamp, horizon, power_outage, riot_scan.
2. For each domain (operation, security, contraband, scanner, power, riot):
   a. Assign "risk_level":"LOW|MEDIUM|HIGH"
   b. "cause": explain (e.g., "Humidity spike", "Power outage imminent", "Riot bio-signature")
   c. "broken": what is at fault (hardware, software, sensor, human, system, or null)
3. If risk is not "LOW" or anything is broken, output [action]...[/action] for mitigation.
4. Only output JSON.
5. Include: "risk_profile" (human summary) and "global_risk_level": highest of all
6. Example neutral:
{
  "operation":{"risk_level":"LOW","cause":"All operational readings stable and within neutral ranges.","broken":null},
  "security":{"risk_level":"LOW","cause":"No anomalies or suspicious activity detected.","broken":null},
  "contraband":{"risk_level":"LOW","cause":"Contraband detectors report nominal status.","broken":null},
  "scanner":{"risk_level":"LOW","cause":"All environmental and contraband scanners are functioning correctly.","broken":null},
  "power":{"risk_level":"LOW","cause":"Power systems are fully stable. No outages or fluctuations.","broken":null},
  "riot":{"risk_level":"LOW","cause":"No unusual population movement. Bio-signature clusters are normal.","broken":null},
  "risk_profile":"All facility systems and security domains are functioning normally. No current risk.",
  "global_risk_level":"LOW"
}
7. Example risk:
{
  "operation":{"risk_level":"MEDIUM","cause":"Motion/riot cluster","broken":"bio scanner"},
  "security":{"risk_level":"HIGH","cause":"Power outage risk","broken":"grid"},
  "contraband":{"risk_level":"LOW","cause":"All detectors nominal","broken":null},
  "scanner":{"risk_level":"HIGH","cause":"Contraband sensor offline","broken":"contraband scanner"},
  "power":{"risk_level":"HIGH","cause":"Storm grid drop","broken":"substation"},
  "riot":{"risk_level":"HIGH","cause":"Red cluster in yard","broken":"population"},
  "risk_profile":"Riot forming + power outage risk.",
  "global_risk_level":"HIGH",
  "[action]":"LOCKDOWN: Riot and power outage imminent. Prep teams, secure all pods.[/action]"
}
"""

# ========== LLM UTILS ==========

async def call_llm(messages, model=None, timeout=40):
    headers = {"Authorization":f"Bearer {LLM_API_KEY}","Content-Type":"application/json"}
    payload = {"model":model or MODEL,"temperature":0,"messages":messages}
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(LLM_ENDPOINT, headers=headers, json=payload)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        try: return json.loads(content)
        except Exception: return content

async def fetch_htscanner_sensors():
    messages = [
        {"role": "system", "content": f"You are g_htscanner at {FACILITY_NAME}."},
        {"role": "user",   "content": G_HTSCANNER_SENSOR_PROMPT}
    ]
    res = await call_llm(messages)
    if isinstance(res, dict): return res
    try: return json.loads(res)
    except Exception: return {"motion": 10, "temp_c": 21, "humidity": 45, "grid_freq": 60.004}

async def fetch_htscanner_date():
    messages = [
        {"role": "system", "content": f"You are g_htscanner date for {FACILITY_NAME}."},
        {"role": "user",   "content": HTSCANNER_DATE_PROMPT}
    ]
    res = await call_llm(messages)
    if isinstance(res, dict) and "current_date" in res: return res["current_date"]
    if isinstance(res, str): return res.strip()
    return datetime.utcnow().isoformat() + "Z"

# ====== SUBMODEL CALLS ======
async def power_outage_future_scan(sensors):
    messages = [
        {"role": "system", "content": "You are the power outage future scan node."},
        {"role": "user", "content": POWER_OUTAGE_FUTURE_PROMPT + "\nSensors: " + json.dumps(sensors)}
    ]
    return await call_llm(messages, model=POWER_OUTAGE_MODEL)

async def riot_detector_scan(timestamp, population=150, color_dist=None):
    if color_dist is None:
        colors = [chr(65+i) for i in range(25)]
        color_dist = {c: 6 for c in colors}
    messages = [
        {"role": "system", "content": "You are the riot bio-mass event detector node."},
        {"role": "user", "content": RIOT_DETECTOR_PROMPT + "\nInput: " +
            json.dumps({"timestamp":timestamp, "population":population, "bio_color_counts":color_dist, "alert_sensors":[]})}
    ]
    return await call_llm(messages, model=RIOT_MODEL)

# ====== TELEMETRY, ENCRYPTION, PARSING ======

def entropy_key(entropy_hash_b64: str) -> bytes:
    # Use entropy hash (telemetry) as part of HKDF info for key rotation
    return derive_key(
        master=LLM_API_KEY.encode(),
        info=base64.b64decode(entropy_hash_b64) + b"QuantumAlcatrazRotation"
    )

async def collect_telemetry():
    cpu    = psutil.cpu_percent(interval=1)
    mem    = psutil.virtual_memory().percent
    disk   = psutil.disk_usage('/').percent
    net    = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
    sensors= await fetch_htscanner_sensors()
    motion,temp_c,humidity,grid_freq = sensors.get("motion"), sensors.get("temp_c"), sensors.get("humidity"), sensors.get("grid_freq")
    raw    = f"{cpu}-{mem}-{disk}-{net}-{motion}-{temp_c}-{humidity}-{grid_freq}"
    h1     = hashlib.sha256(raw.encode()).digest()
    h2     = hashlib.sha256(h1).digest()
    digest = bytes(a ^ b for a, b in zip(h1, h2))
    ent_hash= base64.b64encode(digest).decode()
    color_idx=digest[0]%25
    return {
        "cpu":cpu, "mem":mem, "disk":disk, "net_io":net,
        "motion":motion, "temp_c":temp_c, "humidity":humidity, "grid_freq":grid_freq,
        "entropy_hash":ent_hash, "color_index":color_idx
    }

def encrypt_payload_aesgcm(plaintext: str, key: bytes) -> str:
    # AES-GCM encryption with a fresh 12-byte nonce
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_payload_aesgcm(ciphertext_b64: str, key: bytes) -> str:
    aesgcm = AESGCM(key)
    data = base64.b64decode(ciphertext_b64)
    nonce, ct = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ct, None).decode()

ACTION_BLOCK = re.compile(r"action(.*?)/action", re.DOTALL | re.IGNORECASE)
RISK_PROFILE_BLOCK = re.compile(r'"risk_profile"\s*:\s*"([^"]+)"', re.DOTALL)
LEVEL_BLOCK = re.compile(
    r'"(\w+)"\s*:\s*\{[^\}]*?"risk_level"\s*:\s*"(\w+)"[,\s]*"cause"\s*:\s*"([^"]*)"[,\s]*"broken"\s*:\s*"?(.*?)"?[,\s]*\}',
    re.DOTALL
)
def parse_risk_fields(json_blob: str):
    profile, action = None, None
    match_profile = RISK_PROFILE_BLOCK.search(json_blob)
    if match_profile: profile = match_profile.group(1)
    match_action = ACTION_BLOCK.search(json_blob)
    if match_action: action = match_action.group(1).strip()
    levels = {m[0]: {"risk_level": m[1], "cause": m[2], "broken": m[3]} for m in LEVEL_BLOCK.findall(json_blob)}
    return profile, action, levels

def build_advanced_risk_prompt(local, remote, future, power_outage, riot_scan, horizon, timestamp):
    user_content = ADVANCED_RISK_ANALYSIS_PROMPT.format(
        facility=FACILITY_NAME,
        horizon=horizon,
        timestamp=timestamp,
        local=json.dumps(local),
        remote=json.dumps(remote),
        future=json.dumps(future),
        power_outage=json.dumps(power_outage),
        riot_scan=json.dumps(riot_scan)
    )
    return [
        {"role": "system", "content": "You are the security risk profiler for this facility."},
        {"role": "user", "content": user_content}
    ]

# ========== LOOP ==========
async def advanced_risk_loop():
    interval = BASE_INTERVAL_SEC
    cycle = 0
    while True:
        cycle += 1
        now = await fetch_htscanner_date()
        print(f"\n[QuantumAlcatraz: Scan #{cycle} @ {now}]")
        local  = await collect_telemetry()
        remote = await collect_telemetry()
        future = await fetch_htscanner_sensors()
        power_outage = await power_outage_future_scan(future)
        riot_scan    = await riot_detector_scan(now)
        prompt = build_advanced_risk_prompt(local, remote, future, power_outage, riot_scan, "hourly", now)
        res    = await call_llm(prompt)
        risk_blob = json.dumps(res)
        # ROTATE AES-GCM KEY using entropy hash from telemetry
        enc_key = entropy_key(local["entropy_hash"])
        enc    = encrypt_payload_aesgcm(risk_blob, enc_key)
        print("→ Encrypted (AES-GCM, key rotated):", enc[:60], "…")
        profile, action, domains = parse_risk_fields(risk_blob)
        print("Risk Profile:", profile)
        print("Action Block:", action)
        print("Per-domain levels:", json.dumps(domains, indent=2))
        print(f"⏱ Next in {interval:.1f}s")
        await asyncio.sleep(interval)

async def main():
    print(f"QuantumAlcatraz – Multi-model Power+Riot+Risk – Mode: {'AUTONOMOUS' if AUTONOMOUS_MODE else 'MANUAL'}")
    if AUTONOMOUS_MODE:
        await advanced_risk_loop()
    else:
        now = await fetch_htscanner_date()
        print(f"\n--- Manual Advanced Risk Scan @ {now} ---")
        local = await collect_telemetry()
        remote = await collect_telemetry()
        future = await fetch_htscanner_sensors()
        power_outage = await power_outage_future_scan(future)
        riot_scan    = await riot_detector_scan(now)
        prompt = build_advanced_risk_prompt(local, remote, future, power_outage, riot_scan, "hourly", now)
        res = await call_llm(prompt)
        risk_blob = json.dumps(res)
        enc_key = entropy_key(local["entropy_hash"])
        enc = encrypt_payload_aesgcm(risk_blob, enc_key)
        print(json.dumps(res, indent=2))
        profile, action, domains = parse_risk_fields(risk_blob)
        print("Risk Profile:", profile)
        print("Action Block:", action)
        print("Per-domain levels:", json.dumps(domains, indent=2))
        print("Encrypted output:", enc[:60], "...")

if __name__ == "__main__":
    try:
        asyncio.run
