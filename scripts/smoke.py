"""Signature-admission smoke test run inside the one-shot ``verify`` service.

It generates a fresh keypair, declares the public key, starts the real HTTP
server on an ephemeral port, exercises accept/retry/reject paths and scheduled
activations (including crossing the agreed UTC second), then restarts a second
server against the same database to prove head/effective persistence.

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


def request(port: int, method: str, path: str, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn.request(method, path, body=json.dumps(body) if body is not None else None,
                 headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, (json.loads(raw) if raw else {})


def utc_second(offset: float = 0.0) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset))


def wait_until_second(target: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while utc_second() < target:
        if time.time() > deadline:
            raise TimeoutError(f"scheduled second {target} never arrived")
        time.sleep(0.05)


def signed_envelope(seed, key_id, att_id, doc):
    payload = json.dumps(doc, separators=(",", ":")).encode()
    return {
        "attestationId": att_id,
        "keyId": key_id,
        "payloadBase64": base64.b64encode(payload).decode(),
        "signatureBase64": base64.b64encode(ed25519.sign(payload, seed)).decode(),
    }


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="smoke-")
    db_path = os.path.join(tmp, "att.db")
    keys_path = os.path.join(tmp, "keys.json")

    seed = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1" "66d38535076f094b85ce3a2e0b4458f7")
    public = ed25519.publickey(seed)
    key_id = "smoke-vendor"
    device = "smoke-sat-1"
    with open(keys_path, "w", encoding="utf-8") as fh:
        # Unbound key so the smoke can exercise a second (pending) device.
        json.dump({"keys": {key_id: {
            "algorithm": "Ed25519",
            "publicKeyBase64": base64.b64encode(public).decode(),
        }}}, fh)

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
        envelope = signed_envelope(seed, key_id, "smoke-att-1", doc1)
        status, body = request(port, "POST", "/api/attestations", envelope)
        check("first attestation accepted (201)", status == 201, f"{status} {body}")
        check("immediate acceptance omits activateAt",
              "activateAt" not in body, f"{body}")

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
        env2 = signed_envelope(seed, key_id, "smoke-att-2", doc2)
        status, body = request(port, "POST", "/api/attestations", env2)
        check("successor accepted (201)", status == 201, f"{status} {body}")

        # stale predecessor conflict (claims 0 while head is 2)
        doc_stale = {"deviceId": device, "generation": 9, "previousGeneration": 0,
                     "configSha256": hashlib.sha256(b"x").hexdigest()}
        env_stale = signed_envelope(seed, key_id, "smoke-att-stale", doc_stale)
        status, body = request(port, "POST", "/api/attestations", env_stale)
        check("stale predecessor conflict",
              status == 409 and body["error"]["code"] == "STALE_PREDECESSOR",
              f"{status} {body}")

        status, body = request(port, "GET", f"/api/devices/{device}/head")
        check("head is generation 2 with v2 digest",
              status == 200 and body.get("generation") == 2
              and body.get("configSha256") == hashlib.sha256(config2).hexdigest(),
              f"{status} {body}")

        # immediate (legacy-style) generations are effective right away
        status, body = request(port, "GET", f"/api/devices/{device}/effective")
        check("effective is generation 2 immediately",
              status == 200 and body.get("generation") == 2
              and "activateAt" not in body, f"{status} {body}")

        # a device whose only accepted plan is still pending has a stable code
        pend = "smoke-sat-pending"
        t_pending = utc_second(120)
        doc_p = {"deviceId": pend, "generation": 1, "previousGeneration": 0,
                 "configSha256": hashlib.sha256(b"pending").hexdigest(),
                 "activateAt": t_pending}
        env_p = signed_envelope(seed, key_id, "smoke-att-p1", doc_p)
        status, body = request(port, "POST", "/api/attestations", env_p)
        check("future plan accepted (admitted != effective)",
              status == 201 and body.get("activateAt") == t_pending, f"{status} {body}")
        status, body = request(port, "GET", f"/api/devices/{pend}/effective")
        check("pending-only device -> NO_EFFECTIVE_CONFIG",
              status == 404 and body["error"]["code"] == "NO_EFFECTIVE_CONFIG",
              f"{status} {body}")

        # malformed activateAt rejected, state untouched
        doc_badts = {"deviceId": pend, "generation": 2, "previousGeneration": 1,
                     "configSha256": hashlib.sha256(b"x").hexdigest(),
                     "activateAt": "2026-10-07T12:00:00+00:00"}
        env_badts = signed_envelope(seed, key_id, "smoke-att-badts", doc_badts)
        status, body = request(port, "POST", "/api/attestations", env_badts)
        check("bad activateAt rejected",
              status == 400 and body["error"]["code"] == "INVALID_JSON_PAYLOAD",
              f"{status} {body}")

        # scheduled gen 3: accepted now, effective only at the agreed second
        config3 = b"smoke-config-v3"
        t3 = utc_second(2)
        doc3 = {"deviceId": device, "generation": 3, "previousGeneration": 2,
                "configSha256": hashlib.sha256(config3).hexdigest(),
                "activateAt": t3}
        env3 = signed_envelope(seed, key_id, "smoke-att-3", doc3)
        status, body3 = request(port, "POST", "/api/attestations", env3)
        check("scheduled gen 3 accepted (201)",
              status == 201 and body3.get("activateAt") == t3, f"{status} {body3}")

        # activation order regression (before previous generation) rejected
        doc_reg = {"deviceId": device, "generation": 4, "previousGeneration": 3,
                   "configSha256": hashlib.sha256(b"reg").hexdigest(),
                   "activateAt": "2000-01-01T00:00:00Z"}
        env_reg = signed_envelope(seed, key_id, "smoke-att-reg", doc_reg)
        status, body = request(port, "POST", "/api/attestations", env_reg)
        check("activation order regression rejected",
              status == 409
              and body["error"]["code"] == "ACTIVATION_TIME_NOT_ADVANCED",
              f"{status} {body}")

        # before the second arrives the old generation keeps serving
        status, body = request(port, "GET", f"/api/devices/{device}/effective")
        check("old gen 2 effective while gen 3 pending",
              status == 200 and body.get("generation") == 2, f"{status} {body}")
        status, body = request(port, "GET", f"/api/devices/{device}/head")
        check("head already gen 3 while effective is gen 2",
              body.get("generation") == 3, f"{status} {body}")

        # cross the agreed UTC second: the unique new generation appears
        wait_until_second(t3)
        flipped = None
        deadline = time.time() + 5
        while time.time() < deadline:
            status, body = request(port, "GET", f"/api/devices/{device}/effective")
            if status == 200 and body.get("generation") == 3:
                flipped = body
                break
            time.sleep(0.1)
        check("after the second, effective flips to unique gen 3",
              flipped is not None
              and flipped.get("configSha256") == hashlib.sha256(config3).hexdigest()
              and flipped.get("activateAt") == t3,
              f"{flipped}")

        # retry AFTER time passed replays the original result, creates nothing
        status, body = request(port, "POST", "/api/attestations", env3)
        check("post-boundary retry replays duplicate",
              status == 200 and body.get("status") == "duplicate"
              and body.get("acceptedAt") == body3.get("acceptedAt")
              and body.get("activateAt") == t3, f"{status} {body}")
        status, body = request(port, "GET", f"/api/devices/{device}/head")
        check("no new record after replay (head stays gen 3)",
              body.get("generation") == 3
              and body.get("attestationId") == "smoke-att-3", f"{status} {body}")
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
              status == 200 and body.get("generation") == 3
              and body.get("configSha256") == hashlib.sha256(config3).hexdigest()
              and body.get("attestationId") == "smoke-att-3",
              f"{status} {body}")
        status, body = request(port2, "GET", f"/api/devices/{device}/effective")
        check("effective gen 3 survives restart",
              status == 200 and body.get("generation") == 3
              and body.get("activateAt") == t3, f"{status} {body}")

        # pending plan on the other device is still pending after restart
        status, body = request(port2, "GET", f"/api/devices/{pend}/effective")
        check("pending device still NO_EFFECTIVE_CONFIG after restart",
              status == 404 and body["error"]["code"] == "NO_EFFECTIVE_CONFIG",
              f"{status} {body}")

        # unknown device
        status, body = request(port2, "GET", "/api/devices/unknown/head")
        check("unknown device 404", status == 404
              and body["error"]["code"] == "DEVICE_NOT_FOUND", f"{status} {body}")
        status, body = request(port2, "GET", "/api/devices/unknown/effective")
        check("unknown device effective 404", status == 404
              and body["error"]["code"] == "DEVICE_NOT_FOUND", f"{status} {body}")
    finally:
        server2.shutdown()
        server2.server_close()

    print(f"[smoke] {FAILURES} failure(s)")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
