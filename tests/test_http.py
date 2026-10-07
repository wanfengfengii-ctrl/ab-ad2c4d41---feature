"""End-to-end HTTP tests against a live server instance."""

import base64
import hashlib
import http.client
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from app import ed25519
from app.server import build_server

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SEED = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1" "66d38535076f094b85ce3a2e0b4458f7")
PUB = ed25519.publickey(SEED)
KEY_ID = "http-vendor"


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


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

    # ------------------------------------------------------ scheduled plans
    def test_immediate_response_shape_unchanged(self):
        body = self.attestation_body("imm-1", "sat-imm", 1, 0, b"c")
        s, r = self.req("POST", "/api/attestations", body)
        self.assertEqual(s, 201)
        self.assertNotIn("activateAt", r)
        s, r = self.req("GET", "/api/devices/sat-imm/effective")
        self.assertEqual(s, 200)
        self.assertEqual(r["generation"], 1)
        self.assertNotIn("activateAt", r)

    def test_effective_unknown_and_pending(self):
        # completely unknown device
        s, r = self.req("GET", "/api/devices/nope-dev/effective")
        self.assertEqual(s, 404)
        self.assertEqual(r["error"]["code"], "DEVICE_NOT_FOUND")

        # known device whose only accepted generation is still in the future
        future = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 120))
        body = self.attestation_body("pend-1", "sat-pend", 1, 0, b"c",
                                     activate_at=future)
        s, r = self.req("POST", "/api/attestations", body)
        self.assertEqual(s, 201, r)
        self.assertEqual(r["activateAt"], future)
        # head is accepted immediately ...
        s, head = self.req("GET", "/api/devices/sat-pend/head")
        self.assertEqual(head["generation"], 1)
        # ... but effective reports a stable "not yet" code
        s, r = self.req("GET", "/api/devices/sat-pend/effective")
        self.assertEqual(s, 404)
        self.assertEqual(r["error"]["code"], "NO_EFFECTIVE_CONFIG")

    def test_invalid_activate_at_rejected_without_state_change(self):
        for bad in ["2026-10-07T12:00:00+00:00", "2026-10-07T12:00",
                    "2026-10-07T12:00:00.5Z", "2026-13-40T99:00:00Z"]:
            body = self.attestation_body(
                f"bad-{bad}", "sat-badts", 1, 0, b"c", activate_at=bad)
            s, r = self.req("POST", "/api/attestations", body)
            self.assertEqual(s, 400, r)
            self.assertEqual(r["error"]["code"], "INVALID_JSON_PAYLOAD", bad)
        s, r = self.req("GET", "/api/devices/sat-badts/head")
        self.assertEqual(s, 404)

    def test_activation_order_regression_rejected(self):
        t1 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 60))
        t0 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60))
        b1 = self.attestation_body("ord-1", "sat-ord", 1, 0, b"c1",
                                   activate_at=t1)
        self.assertEqual(self.req("POST", "/api/attestations", b1)[0], 201)
        b2 = self.attestation_body("ord-2", "sat-ord", 2, 1, b"c2",
                                   activate_at=t0)
        s, r = self.req("POST", "/api/attestations", b2)
        self.assertEqual(s, 409)
        self.assertEqual(r["error"]["code"], "ACTIVATION_TIME_NOT_ADVANCED")
        # head unchanged
        s, head = self.req("GET", "/api/devices/sat-ord/head")
        self.assertEqual(head["generation"], 1)

    def test_cross_second_boundary_flips_unique_generation(self):
        device = "sat-flip"
        # gen 1 effective immediately
        b1 = self.attestation_body("flip-1", device, 1, 0, b"c1")
        self.assertEqual(self.req("POST", "/api/attestations", b1)[0], 201)
        # gen 2 scheduled a few seconds out
        due = time.gmtime(time.time() + 3)
        t2 = time.strftime("%Y-%m-%dT%H:%M:%SZ", due)
        b2 = self.attestation_body("flip-2", device, 2, 1, b"c2",
                                   activate_at=t2)
        s, r = self.req("POST", "/api/attestations", b2)
        self.assertEqual(s, 201, r)
        # until the second arrives, old generation keeps serving
        s, r = self.req("GET", f"/api/devices/{device}/effective")
        self.assertEqual(r["generation"], 1)
        self.assertEqual(r["configSha256"], h(b"c1"))

        # exact retry after the boundary replays the original acceptance
        deadline = time.time() + 10
        while time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) < t2:
            self.assertLess(time.time(), deadline, "scheduled second never arrived")
            time.sleep(0.1)
        # at/past the second, the unique new generation is observable
        deadline = time.time() + 5
        while True:
            s, r = self.req("GET", f"/api/devices/{device}/effective")
            if r.get("generation") == 2:
                break
            self.assertLess(time.time(), deadline, f"never flipped: {r}")
            time.sleep(0.1)
        self.assertEqual(s, 200)
        self.assertEqual(r["configSha256"], h(b"c2"))
        self.assertEqual(r["activateAt"], t2)

        # retry after time passed -> duplicate, no new record
        s, r = self.req("POST", "/api/attestations", b2)
        self.assertEqual((s, r["status"]), (200, "duplicate"))
        self.assertEqual(r["activateAt"], t2)
        s, head = self.req("GET", f"/api/devices/{device}/head")
        self.assertEqual(head["generation"], 2)


class RestartEffectiveTests(unittest.TestCase):
    """Pending schedules keep their effective semantics across a restart."""

    def test_effective_survives_restart(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        keys_path = os.path.join(tmp.name, "keys.json")
        db_path = os.path.join(tmp.name, "att.db")
        with open(keys_path, "w") as fh:
            json.dump({"keys": {KEY_ID: {
                "algorithm": "Ed25519",
                "publicKeyBase64": base64.b64encode(PUB).decode(),
            }}}, fh)

        def serve():
            srv = build_server("127.0.0.1", 0, db_path, keys_path)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            time.sleep(0.05)
            return srv, port

        def req(port, method, path, body=None):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            headers = {"Content-Type": "application/json"} if body is not None else {}
            conn.request(method, path,
                         body=json.dumps(body) if body is not None else None,
                         headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            conn.close()
            return resp.status, json.loads(raw) if raw else {}

        def body_for(att_id, gen, prev, config, activate_at=None):
            doc = {"deviceId": "sat-rst", "generation": gen,
                   "previousGeneration": prev, "configSha256": h(config)}
            if activate_at:
                doc["activateAt"] = activate_at
            payload = json.dumps(doc, separators=(",", ":")).encode()
            return {
                "attestationId": att_id, "keyId": KEY_ID,
                "payloadBase64": base64.b64encode(payload).decode(),
                "signatureBase64": base64.b64encode(
                    ed25519.sign(payload, SEED)).decode(),
            }

        srv, port = serve()
        try:
            self.assertEqual(
                req(port, "POST", "/api/attestations",
                    body_for("rst-1", 1, 0, b"c1"))[0], 201)
            future = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 300))
            s, r = req(port, "POST", "/api/attestations",
                       body_for("rst-2", 2, 1, b"c2", future))
            self.assertEqual(s, 201, r)
        finally:
            srv.shutdown()
            srv.server_close()

        # restart against the same database file
        srv2, port2 = serve()
        try:
            s, r = req(port2, "GET", "/api/devices/sat-rst/effective")
            self.assertEqual(s, 200)
            self.assertEqual(r["generation"], 1)
            s, r = req(port2, "GET", "/api/devices/sat-rst/head")
            self.assertEqual(r["generation"], 2)
        finally:
            srv2.shutdown()
            srv2.server_close()


class KillNineRestartTests(unittest.TestCase):
    """Real server process killed with SIGKILL keeps head AND pending plans."""

    SEED = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1"
                         "66d38535076f094b85ce3a2e0b4458f7")
    KEY_ID = "k9-vendor"
    DEVICE = "k9-sat"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "att.db")
        self.keys_path = os.path.join(self.tmp.name, "keys.json")
        with open(self.keys_path, "w") as fh:
            json.dump({"keys": {self.KEY_ID: {
                "algorithm": "Ed25519",
                "publicKeyBase64": base64.b64encode(
                    ed25519.publickey(self.SEED)).decode(),
            }}}, fh)
        self.procs = []

    def tearDown(self):
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
        self.tmp.cleanup()

    def _start(self):
        env = dict(os.environ, DB_PATH=self.db_path, KEYS_PATH=self.keys_path,
                   APP_HOST="127.0.0.1", APP_PORT="0", QUIET_LOGS="1",
                   PYTHONPATH=REPO_ROOT)
        proc = subprocess.Popen(
            [sys.executable, "-m", "app.server"],
            cwd=REPO_ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.procs.append(proc)
        port = None
        # the server prints its bound port on startup:
        # "attestation guard listening on 127.0.0.1:<port> (db=...)"
        while True:
            line = proc.stdout.readline()
            if not line:
                raise RuntimeError("server exited before announcing port")
            marker = "listening on "
            if marker in line:
                port = int(line.split(marker, 1)[1]
                           .rsplit(":", 1)[1].split(" ", 1)[0])
                break
        return proc, port

    def _req(self, port, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        headers = {"Content-Type": "application/json"} if body is not None else {}
        conn.request(method, path,
                     body=json.dumps(body) if body is not None else None,
                     headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw) if raw else {}

    def _env(self, att_id, gen, prev, config, activate_at=None):
        doc = {"deviceId": self.DEVICE, "generation": gen,
               "previousGeneration": prev, "configSha256": h(config)}
        if activate_at:
            doc["activateAt"] = activate_at
        payload = json.dumps(doc, separators=(",", ":")).encode()
        return {
            "attestationId": att_id, "keyId": self.KEY_ID,
            "payloadBase64": base64.b64encode(payload).decode(),
            "signatureBase64": base64.b64encode(
                ed25519.sign(payload, self.SEED)).decode(),
        }

    def test_kill9_then_restart_preserves_pending_and_flips_after_boundary(self):
        proc, port = self._start()
        self.assertEqual(
            self._req(port, "POST", "/api/attestations",
                      self._env("k9-1", 1, 0, b"c1"))[0], 201)
        # gen 2 admitted now but due a few seconds later
        t2 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3))
        s, r = self._req(port, "POST", "/api/attestations",
                         self._env("k9-2", 2, 1, b"c2", t2))
        self.assertEqual(s, 201, r)

        s, r = self._req(port, "GET", f"/api/devices/{self.DEVICE}/effective")
        self.assertEqual((s, r["generation"]), (200, 1))

        # hard kill (SIGKILL) while gen 2 is still pending, no graceful shutdown
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=5)

        # restart against the same on-disk database
        proc2, port2 = self._start()
        try:
            s, r = self._req(port2, "GET", f"/api/devices/{self.DEVICE}/head")
            self.assertEqual((s, r["generation"]), (200, 2))
            # gen 2 still pending: old gen 1 remains effective after restart
            s, r = self._req(port2, "GET",
                             f"/api/devices/{self.DEVICE}/effective")
            self.assertEqual((s, r["generation"]), (200, 1))

            # cross the scheduled second after the restart
            deadline = time.time() + 10
            while time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) < t2:
                self.assertLess(time.time(), deadline)
                time.sleep(0.1)
            flipped = False
            deadline = time.time() + 5
            while time.time() < deadline:
                s, r = self._req(port2, "GET",
                                 f"/api/devices/{self.DEVICE}/effective")
                if r.get("generation") == 2:
                    self.assertEqual(r["configSha256"], h(b"c2"))
                    self.assertEqual(r["activateAt"], t2)
                    flipped = True
                    break
                time.sleep(0.1)
            self.assertTrue(flipped, "effective never flipped after restart")
        finally:
            proc2.send_signal(signal.SIGKILL)
            proc2.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
