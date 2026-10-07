"""Signature-admission smoke test run inside the one-shot ``verify`` service.

It generates a fresh keypair, declares the public key, starts the real HTTP
server on an ephemeral port, exercises accept/retry/reject paths, then restarts
a second server against the same database to prove head persistence.

Exit code is non-zero (count of failures) if any check fails.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import ed25519
from app.server import build_server

FAILURES = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    mark = "PASS" if condition else "FAIL"
    print(f"[smoke:{mark}] {name}{(' - ' + detail) if detail and not condition else ''}")
    global FAILURES
    if not condition:
        FAILURES += 1


def utc_stamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def signed_envelope(att_id, key_id, device, gen, prev, config, seed,
                    activate_at=None):
    doc = {
        "deviceId": device,
        "generation": gen,
        "previousGeneration": prev,
        "configSha256": hashlib.sha256(config).hexdigest(),
    }
    if activate_at is not None:
        doc["activateAt"] = activate_at
    payload = json.dumps(doc, separators=(",", ":")).encode()
    return {
        "attestationId": att_id,
        "keyId": key_id,
        "payloadBase64": base64.b64encode(payload).decode(),
        "signatureBase64": base64.b64encode(ed25519.sign(payload, seed)).decode(),
    }


def wait_for_effective(port, device, generation, timeout=10.0):
    """Poll /effective until it reports ``generation`` (or time out)."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        status, body = request(port, "GET", f"/api/devices/{device}/effective")
        last = (status, body)
        if status == 200 and body.get("generation") == generation:
            return True, body
        time.sleep(0.1)
    return False, last


def request(port: int, method: str, path: str, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn.request(method, path, body=json.dumps(body) if body is not None else None,
                 headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, (json.loads(raw) if raw else {})


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="smoke-")
    db_path = os.path.join(tmp, "att.db")
    keys_path = os.path.join(tmp, "keys.json")

    seed = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1" "66d38535076f094b85ce3a2e0b4458f7")
    public = ed25519.publickey(seed)
    key_id = "smoke-vendor"
    device = "smoke-sat-1"
    # A second, unbound key lets the smoke exercise an unrelated device.
    seed2 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4" "4449c5697b326919703bac031cae7f60")
    public2 = ed25519.publickey(seed2)
    key_id2 = "smoke-vendor-unbound"
    with open(keys_path, "w", encoding="utf-8") as fh:
        json.dump({"keys": {
            key_id: {
                "algorithm": "Ed25519",
                "publicKeyBase64": base64.b64encode(public).decode(),
                "deviceId": device,
            },
            key_id2: {
                "algorithm": "Ed25519",
                "publicKeyBase64": base64.b64encode(public2).decode(),
            },
        }}, fh)

    server = build_server("127.0.0.1", 0, db_path, keys_path)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)

    try:
        status, body = request(port, "GET", "/healthz")
        check("healthz", status == 200 and body.get("status") == "ok", f"{status} {body}")

        config1 = b"smoke-config-v1"
        doc1 = {
            "deviceId": device,
            "generation": 1,
            "previousGeneration": 0,
            "configSha256": hashlib.sha256(config1).hexdigest(),
        }
        payload1 = json.dumps(doc1, separators=(",", ":")).encode()
        envelope = {
            "attestationId": "smoke-att-1",
            "keyId": key_id,
            "payloadBase64": base64.b64encode(payload1).decode(),
            "signatureBase64": base64.b64encode(ed25519.sign(payload1, seed)).decode(),
        }
        status, body = request(port, "POST", "/api/attestations", envelope)
        check("first attestation accepted (201)", status == 201, f"{status} {body}")

        # exact retry -> original result, no state change
        status, body = request(port, "POST", "/api/attestations", envelope)
        check("identical retry is duplicate (200)",
              status == 200 and body.get("status") == "duplicate", f"{status} {body}")

        # wrong signature rejected, state untouched
        bad = dict(envelope)
        bad["signatureBase64"] = base64.b64encode(b"\x00" * 64).decode()
        status, body = request(port, "POST", "/api/attestations", bad)
        check("bad signature rejected",
              status == 401 and body["error"]["code"] == "INVALID_SIGNATURE", f"{status} {body}")

        # unknown key rejected
        bad_key = dict(envelope)
        bad_key["attestationId"] = "smoke-att-x"
        bad_key["keyId"] = "does-not-exist"
        status, body = request(port, "POST", "/api/attestations", bad_key)
        check("unknown key rejected",
              status == 401 and body["error"]["code"] == "UNKNOWN_KEY_ID", f"{status} {body}")

        # successor chaining
        config2 = b"smoke-config-v2"
        doc2 = {"deviceId": device, "generation": 2, "previousGeneration": 1,
                "configSha256": hashlib.sha256(config2).hexdigest()}
        payload2 = json.dumps(doc2, separators=(",", ":")).encode()
        env2 = {
            "attestationId": "smoke-att-2",
            "keyId": key_id,
            "payloadBase64": base64.b64encode(payload2).decode(),
            "signatureBase64": base64.b64encode(ed25519.sign(payload2, seed)).decode(),
        }
        status, body = request(port, "POST", "/api/attestations", env2)
        check("successor accepted (201)", status == 201, f"{status} {body}")

        # stale predecessor conflict (claims 0 while head is 2)
        doc_stale = {"deviceId": device, "generation": 9, "previousGeneration": 0,
                     "configSha256": hashlib.sha256(b"x").hexdigest()}
        p_stale = json.dumps(doc_stale, separators=(",", ":")).encode()
        env_stale = {
            "attestationId": "smoke-att-stale",
            "keyId": key_id,
            "payloadBase64": base64.b64encode(p_stale).decode(),
            "signatureBase64": base64.b64encode(ed25519.sign(p_stale, seed)).decode(),
        }
        status, body = request(port, "POST", "/api/attestations", env_stale)
        check("stale predecessor conflict",
              status == 409 and body["error"]["code"] == "STALE_PREDECESSOR",
              f"{status} {body}")

        status, body = request(port, "GET", f"/api/devices/{device}/head")
        check("head is generation 2 with v2 digest",
              status == 200 and body.get("generation") == 2
              and body.get("configSha256") == hashlib.sha256(config2).hexdigest(),
              f"{status} {body}")

        # ---- scheduled activation continues on the bound device -----------
        # gens 1 and 2 above are immediate; admit an immediate gen 3 first.
        env_s1 = signed_envelope("smoke-sched-1", key_id, device, 3, 2,
                                 b"sched-config-v1", seed)
        status, body = request(port, "POST", "/api/attestations", env_s1)
        check("gen 3 accepted immediately",
              status == 201 and "activateAt" not in body, f"{status} {body}")
        status, body = request(port, "GET", f"/api/devices/{device}/effective")
        check("effective is gen 3 before schedule arrives",
              status == 200 and body.get("generation") == 3, f"{status} {body}")

        activate = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=6)
        activate_stamp = utc_stamp(activate)
        env_s2 = signed_envelope("smoke-sched-2", key_id, device, 4, 3,
                                 b"sched-config-v2", seed, activate_at=activate_stamp)
        status, body = request(port, "POST", "/api/attestations", env_s2)
        check("scheduled gen 4 admitted (201) with activateAt",
              status == 201 and body.get("activateAt") == activate_stamp,
              f"{status} {body}")

        status, head = request(port, "GET", f"/api/devices/{device}/head")
        check("scheduled gen 4 is the admitted head immediately",
              status == 200 and head.get("generation") == 4, f"{status} {head}")
        status, eff = request(port, "GET", f"/api/devices/{device}/effective")
        check("effective stays gen 3 while gen 4 is pending",
              status == 200 and eff.get("generation") == 3
              and eff.get("configSha256") == hashlib.sha256(b"sched-config-v1").hexdigest(),
              f"{status} {eff}")

        # illegal timestamp must be rejected without touching state
        env_badtime = signed_envelope("smoke-sched-bad", key_id, device, 5, 4,
                                      b"sched-config-v3", seed,
                                      activate_at="2026-13-40T99:00:00Z")
        status, body = request(port, "POST", "/api/attestations", env_badtime)
        check("illegal activateAt rejected",
              status == 400 and body["error"]["code"] == "INVALID_JSON_PAYLOAD",
              f"{status} {body}")

        # activation order regression (gen 5 earlier than gen 4)
        env_regress = signed_envelope("smoke-sched-3", key_id, device, 5, 4,
                                      b"sched-config-v3", seed,
                                      activate_at=utc_stamp(activate - timedelta(seconds=1)))
        status, body = request(port, "POST", "/api/attestations", env_regress)
        check("activation order regression rejected",
              status == 409 and body["error"]["code"] == "ACTIVATION_NOT_ORDERED",
              f"{status} {body}")
        status, eff = request(port, "GET", f"/api/devices/{device}/effective")
        check("state unchanged after rejected schedules",
              eff.get("generation") == 3, f"{status} {eff}")

        # exact retry still replays the original (even once due)
        status, body = request(port, "POST", "/api/attestations", env_s2)
        check("scheduled gen 4 retry is duplicate with original result",
              status == 200 and body.get("status") == "duplicate"
              and body.get("activateAt") == activate_stamp, f"{status} {body}")

        # cross the agreed second: a unique new generation becomes effective
        flipped, body = wait_for_effective(port, device, 4, timeout=8)
        check("only gen 4 is effective after crossing activateAt",
              flipped and body.get("configSha256")
              == hashlib.sha256(b"sched-config-v2").hexdigest()
              and body.get("attestationId") == "smoke-sched-2",
              f"{body}")
        status, body = request(port, "GET", f"/api/devices/{device}/effective")
        check("effective stays uniquely gen 4 afterwards",
              status == 200 and body.get("generation") == 4, f"{status} {body}")

        # device whose only config is scheduled in the future: stable error code
        future_dev = "smoke-sat-future"
        env_f = signed_envelope(
            "smoke-future-1", key_id2, future_dev, 1, 0, b"future-config", seed2,
            activate_at=utc_stamp(datetime.now(timezone.utc) + timedelta(hours=1)),
        )
        status, body = request(port, "POST", "/api/attestations", env_f)
        check("future-only device admitted", status == 201, f"{status} {body}")
        status, body = request(port, "GET", f"/api/devices/{future_dev}/effective")
        check("future-only device has no effective config",
              status == 404 and body["error"]["code"] == "NO_EFFECTIVE_CONFIG",
              f"{status} {body}")
    finally:
        server.shutdown()
        server.server_close()

    # ---- restart: brand new server process against the same database -------
    server2 = build_server("127.0.0.1", 0, db_path, keys_path)
    port2 = server2.server_address[1]
    t2 = threading.Thread(target=server2.serve_forever, daemon=True)
    t2.start()
    time.sleep(0.1)
    try:
        status, body = request(port2, "GET", f"/api/devices/{device}/head")
        check("head survives restart",
              status == 200 and body.get("generation") == 4
              and body.get("configSha256") == hashlib.sha256(b"sched-config-v2").hexdigest()
              and body.get("attestationId") == "smoke-sched-2",
              f"{status} {body}")

        # unknown device
        status, body = request(port2, "GET", "/api/devices/unknown/head")
        check("unknown device 404", status == 404
              and body["error"]["code"] == "DEVICE_NOT_FOUND", f"{status} {body}")

        # scheduled activation state survives the restart
        status, body = request(port2, "GET", f"/api/devices/{device}/head")
        check("scheduled head survives restart",
              status == 200 and body.get("generation") == 4
              and body.get("activateAt") == activate_stamp, f"{status} {body}")
        flipped, body = wait_for_effective(port2, device, 4, timeout=8)
        check("scheduled gen 4 effective after restart once due",
              flipped and body.get("attestationId") == "smoke-sched-2", f"{body}")
        status, body = request(port2, "GET", f"/api/devices/{future_dev}/effective")
        check("pending future config still not effective after restart",
              status == 404 and body["error"]["code"] == "NO_EFFECTIVE_CONFIG",
              f"{status} {body}")
        status, body = request(port2, "GET", "/api/devices/ghost2/effective")
        check("unknown device effective 404 stable code",
              status == 404 and body["error"]["code"] == "NO_EFFECTIVE_CONFIG",
              f"{status} {body}")
    finally:
        server2.shutdown()
        server2.server_close()

    print(f"[smoke] {FAILURES} failure(s)")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
