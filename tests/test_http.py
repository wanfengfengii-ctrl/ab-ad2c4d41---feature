"""End-to-end HTTP tests against a live server instance."""

import base64
import hashlib
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone

from app import ed25519
from app.server import build_server

SEED = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1" "66d38535076f094b85ce3a2e0b4458f7")
PUB = ed25519.publickey(SEED)
KEY_ID = "http-vendor"


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def utc_stamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class HttpCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.keys_path = os.path.join(cls.tmp.name, "keys.json")
        cls.db_path = os.path.join(cls.tmp.name, "att.db")
        with open(cls.keys_path, "w") as fh:
            json.dump({"keys": {KEY_ID: {
                "algorithm": "Ed25519",
                "publicKeyBase64": base64.b64encode(PUB).decode(),
            }}}, fh)
        cls.server = build_server("127.0.0.1", 0, cls.db_path, cls.keys_path)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def req(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json"} if body is not None else {}
        conn.request(method, path, body=json.dumps(body) if body is not None else None,
                     headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw) if raw else {}

    def attestation_body(self, att_id, device, gen, prev, config, *, bad_sig=False,
                         key_id=KEY_ID, activate_at=None):
        doc = {"deviceId": device, "generation": gen, "previousGeneration": prev,
               "configSha256": h(config)}
        if activate_at is not None:
            doc["activateAt"] = activate_at
        payload = json.dumps(doc, separators=(",", ":")).encode()
        sig = b"\x00" * 64 if bad_sig else ed25519.sign(payload, SEED)
        return {
            "attestationId": att_id,
            "keyId": key_id,
            "payloadBase64": base64.b64encode(payload).decode(),
            "signatureBase64": base64.b64encode(sig).decode(),
        }

    def test_health(self):
        status, body = self.req("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_full_flow_and_head(self):
        body = self.attestation_body("att-1", "sat-1", 1, 0, b"config-v1")
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 201, resp)
        self.assertEqual(resp["status"], "accepted")

        status, resp = self.req("GET", "/api/devices/sat-1/head")
        self.assertEqual(status, 200)
        self.assertEqual(resp["generation"], 1)
        self.assertEqual(resp["configSha256"], h(b"config-v1"))

        # chain successor
        b2 = self.attestation_body("att-2", "sat-1", 2, 1, b"config-v2")
        status, resp = self.req("POST", "/api/attestations", b2)
        self.assertEqual(status, 201)

        status, resp = self.req("GET", "/api/devices/sat-1/head")
        self.assertEqual(resp["generation"], 2)

    def test_retry_is_idempotent(self):
        body = self.attestation_body("att-r", "sat-r", 1, 0, b"c")
        s1, r1 = self.req("POST", "/api/attestations", body)
        s2, r2 = self.req("POST", "/api/attestations", body)
        self.assertEqual((s1, r1["status"]), (201, "accepted"))
        self.assertEqual((s2, r2["status"]), (200, "duplicate"))

    def test_unknown_device_head(self):
        status, resp = self.req("GET", "/api/devices/ghost/head")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "DEVICE_NOT_FOUND")

    def test_unknown_key_error_code(self):
        body = self.attestation_body("x", "sat-x", 1, 0, b"c", key_id="missing")
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 401)
        self.assertEqual(resp["error"]["code"], "UNKNOWN_KEY_ID")

    def test_bad_signature_error_code(self):
        body = self.attestation_body("x", "sat-x", 1, 0, b"c", bad_sig=True)
        status, resp = self.req("POST", "/api/attestations", body)
        self.assertEqual(status, 401)
        self.assertEqual(resp["error"]["code"], "INVALID_SIGNATURE")

    def test_conflict_error_codes(self):
        self.req("POST", "/api/attestations",
                 self.attestation_body("c1", "sat-c", 1, 0, b"v1"))
        # stale predecessor: head is 1 but request claims predecessor 0
        s, r = self.req("POST", "/api/attestations",
                        self.attestation_body("c2", "sat-c", 3, 0, b"v3"))
        self.assertEqual(s, 409)
        self.assertEqual(r["error"]["code"], "STALE_PREDECESSOR")
        # same id, different content
        s, r = self.req("POST", "/api/attestations",
                        self.attestation_body("c1", "sat-c", 2, 1, b"v2"))
        self.assertEqual(r["error"]["code"], "ATTESTATION_ID_CONTENT_MISMATCH")
        # head not advanced
        s, head = self.req("GET", "/api/devices/sat-c/head")
        self.assertEqual(head["generation"], 1)
        self.assertEqual(head["configSha256"], h(b"v1"))

    def test_malformed_request(self):
        s, r = self.req("POST", "/api/attestations", {"attestationId": "z"})
        self.assertEqual(s, 400)
        self.assertEqual(r["error"]["code"], "MALFORMED_REQUEST")

    def test_unknown_route(self):
        s, _ = self.req("GET", "/nope")
        self.assertEqual(s, 404)

    def test_effective_unknown_device(self):
        s, r = self.req("GET", "/api/devices/ghost/effective")
        self.assertEqual(s, 404)
        self.assertEqual(r["error"]["code"], "NO_EFFECTIVE_CONFIG")

    def test_invalid_activate_at_rejected_without_state_change(self):
        future = "2026-10-07T25:00:00Z"  # impossible hour
        body = self.attestation_body("bad-time", "sat-t", 1, 0, b"c",
                                     activate_at=future)
        s, r = self.req("POST", "/api/attestations", body)
        self.assertEqual(s, 400)
        self.assertEqual(r["error"]["code"], "INVALID_JSON_PAYLOAD")
        s, r = self.req("GET", "/api/devices/sat-t/head")
        self.assertEqual(s, 404)

    def test_scheduled_flow_and_real_time_boundary(self):
        device = "sat-sched"
        # gen 1 is immediately in effect
        b1 = self.attestation_body("sched-1", device, 1, 0, b"config-v1")
        s, r = self.req("POST", "/api/attestations", b1)
        self.assertEqual(s, 201, r)
        self.assertNotIn("activateAt", r)

        s, r = self.req("GET", f"/api/devices/{device}/effective")
        self.assertEqual(s, 200)
        self.assertEqual(r["generation"], 1)

        # gen 2 scheduled a couple of seconds in the future
        activate = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=2)
        stamp = utc_stamp(activate)
        b2 = self.attestation_body("sched-2", device, 2, 1, b"config-v2",
                                   activate_at=stamp)
        s, r = self.req("POST", "/api/attestations", b2)
        self.assertEqual(s, 201, r)
        self.assertEqual(r["activateAt"], stamp)

        # head already advanced, but effective stays on the old generation
        s, head = self.req("GET", f"/api/devices/{device}/head")
        self.assertEqual(head["generation"], 2)
        s, eff = self.req("GET", f"/api/devices/{device}/effective")
        self.assertEqual(eff["generation"], 1)
        self.assertEqual(eff["configSha256"], h(b"config-v1"))

        # an activation regression (gen 3 before gen 2's instant) is rejected
        past = utc_stamp(activate - timedelta(seconds=1))
        b3 = self.attestation_body("sched-3", device, 3, 2, b"config-v3",
                                   activate_at=past)
        s, r = self.req("POST", "/api/attestations", b3)
        self.assertEqual(s, 409)
        self.assertEqual(r["error"]["code"], "ACTIVATION_NOT_ORDERED")

        # retry of gen 2 replays the original result even after time passes
        s, r = self.req("POST", "/api/attestations", b2)
        self.assertEqual(s, 200)
        self.assertEqual(r["status"], "duplicate")
        self.assertEqual(r["activateAt"], stamp)

        # cross the agreed second: exactly one new effective generation
        flipped = False
        deadline = time.time() + 8
        last = None
        while time.time() < deadline:
            s, eff = self.req("GET", f"/api/devices/{device}/effective")
            last = eff
            if eff.get("generation") == 2:
                flipped = True
                break
            time.sleep(0.1)
        self.assertTrue(flipped, f"effective never flipped to gen 2: {last}")
        self.assertEqual(last["configSha256"], h(b"config-v2"))
        self.assertEqual(last["attestationId"], "sched-2")

        # and it stays the unique effective generation
        s, eff = self.req("GET", f"/api/devices/{device}/effective")
        self.assertEqual(eff["generation"], 2)


if __name__ == "__main__":
    unittest.main()
