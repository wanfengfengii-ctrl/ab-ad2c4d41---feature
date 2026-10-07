"""Scheduled activation: admission, ordering, effective query, migration."""

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone

from app import ed25519
from app.admit import Admitter
from app.store import Store

SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PUB = ed25519.publickey(SEED)
KEY_ID = "vendor-1"


def digest(config: bytes) -> str:
    return hashlib.sha256(config).hexdigest()


def utc_stamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class ScheduleCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "att.db")
        self.store = Store(self.db)
        self.admitter = Admitter(self.store, {KEY_ID: PUB}, {KEY_ID: None})

    def tearDown(self):
        self.tmp.cleanup()

    def submit(self, att_id, device, gen, prev, config, *, activate_at=None):
        doc = {
            "deviceId": device,
            "generation": gen,
            "previousGeneration": prev,
            "configSha256": digest(config),
        }
        if activate_at is not None:
            doc["activateAt"] = activate_at
        payload = json.dumps(doc, separators=(",", ":")).encode("utf-8")
        sig = ed25519.sign(payload, SEED)
        return self.admitter.admit(
            attestation_id=att_id,
            key_id=KEY_ID,
            payload_b64=base64.b64encode(payload).decode(),
            signature_b64=base64.b64encode(sig).decode(),
        )

    def test_scheduled_head_advances_but_not_effective_until_due(self):
        future = utc_stamp(datetime.now(timezone.utc) + timedelta(days=1))
        d = self.submit("a1", "dev", 1, 0, b"cfg-1", activate_at=future)
        self.assertTrue(d.accepted, d.message)
        self.assertEqual(d.status, 201)
        self.assertEqual(d.record["activateAt"], future)

        # admitted == the accepted head advances immediately ...
        self.assertEqual(self.admitter.head("dev")["generation"], 1)
        # ... but nothing is in effect yet.
        self.assertIsNone(self.admitter.effective("dev"))

        now = utc_stamp(datetime.now(timezone.utc))
        self.assertIsNone(self.store.effective("dev", now))
        # once the instant arrives (or passes) the generation is effective
        self.assertEqual(self.store.effective("dev", future).generation, 1)
        later = utc_stamp(datetime.now(timezone.utc) + timedelta(days=2))
        self.assertEqual(self.store.effective("dev", later).generation, 1)

    def test_old_generation_stays_effective_while_new_head_pending(self):
        past = utc_stamp(datetime.now(timezone.utc) - timedelta(hours=1))
        future = utc_stamp(datetime.now(timezone.utc) + timedelta(hours=1))
        self.assertTrue(
            self.submit("a1", "dev", 1, 0, b"cfg-1", activate_at=past).accepted
        )
        self.assertTrue(
            self.submit("a2", "dev", 2, 1, b"cfg-2", activate_at=future).accepted
        )
        now = utc_stamp(datetime.now(timezone.utc))
        eff = self.store.effective("dev", now)
        self.assertEqual(eff.generation, 1)
        self.assertEqual(eff.config_sha256, digest(b"cfg-1"))
        self.assertEqual(self.admitter.head("dev")["generation"], 2)

    def test_highest_due_generation_wins(self):
        t0 = datetime.now(timezone.utc).replace(microsecond=0)
        stamps = [utc_stamp(t0 + timedelta(seconds=10 * i)) for i in range(1, 4)]
        for i, stamp in enumerate(stamps, start=1):
            d = self.submit(f"a{i}", "dev", i, i - 1, f"cfg-{i}".encode(),
                            activate_at=stamp)
            self.assertTrue(d.accepted, d.message)

        self.assertIsNone(self.store.effective("dev", utc_stamp(t0)))
        self.assertEqual(
            self.store.effective("dev", utc_stamp(t0 + timedelta(seconds=15))).generation,
            1,
        )
        self.assertEqual(
            self.store.effective("dev", utc_stamp(t0 + timedelta(seconds=25))).generation,
            2,
        )
        self.assertEqual(
            self.store.effective("dev", utc_stamp(t0 + timedelta(seconds=30))).generation,
            3,
        )

    def test_activation_time_regression_rejected(self):
        t0 = datetime.now(timezone.utc).replace(microsecond=0)
        later = utc_stamp(t0 + timedelta(hours=10))
        sooner = utc_stamp(t0 + timedelta(hours=1))
        self.assertTrue(
            self.submit("a1", "dev", 1, 0, b"cfg-1", activate_at=later).accepted
        )
        d = self.submit("a2", "dev", 2, 1, b"cfg-2", activate_at=sooner)
        self.assertFalse(d.accepted)
        self.assertEqual(d.status, 409)
        self.assertEqual(d.code, "ACTIVATION_NOT_ORDERED")
        # neither the head nor anything effective changes
        self.assertEqual(self.admitter.head("dev")["generation"], 1)
        self.assertIsNone(self.admitter.effective("dev"))

    def test_immediate_successor_after_future_head_rejected(self):
        future = utc_stamp(datetime.now(timezone.utc) + timedelta(hours=10))
        self.assertTrue(
            self.submit("a1", "dev", 1, 0, b"cfg-1", activate_at=future).accepted
        )
        d = self.submit("a2", "dev", 2, 1, b"cfg-2")  # omitted activateAt
        self.assertEqual(d.code, "ACTIVATION_NOT_ORDERED")
        self.assertEqual(self.admitter.head("dev")["generation"], 1)

    def test_equal_activation_instant_allowed(self):
        t = utc_stamp(datetime.now(timezone.utc) + timedelta(hours=10))
        self.assertTrue(
            self.submit("a1", "dev", 1, 0, b"cfg-1", activate_at=t).accepted
        )
        d = self.submit("a2", "dev", 2, 1, b"cfg-2", activate_at=t)
        self.assertTrue(d.accepted, d.message)

    def test_invalid_activate_at_shapes_rejected_as_payload_errors(self):
        bad_values = [
            "2026-13-01T00:00:00Z",       # impossible month
            "2026-02-30T00:00:00Z",       # impossible day
            "2026-10-07T12:00:00+00:00",  # offset instead of Z
            "2026-10-07T12:00:00",        # missing Z
            "2026-10-07T12:00:00.5Z",     # fractional seconds
            "2026-10-07 12:00:00Z",       # space separator
            12345,                        # not a string
        ]
        for bad in bad_values:
            d = self.submit("a-bad", "dev", 1, 0, b"cfg-1", activate_at=bad)
            self.assertFalse(d.accepted, bad)
            self.assertEqual(d.code, "INVALID_JSON_PAYLOAD", bad)
            self.assertIsNone(self.admitter.head("dev"), bad)

    def test_duplicate_replay_after_time_passes_creates_nothing_new(self):
        future = utc_stamp(datetime.now(timezone.utc) - timedelta(seconds=1))
        doc = {
            "deviceId": "dev",
            "generation": 1,
            "previousGeneration": 0,
            "configSha256": digest(b"cfg-1"),
            "activateAt": future,
        }
        payload = json.dumps(doc, separators=(",", ":")).encode()
        sig = ed25519.sign(payload, SEED)
        kwargs = dict(
            attestation_id="a1",
            key_id=KEY_ID,
            payload_b64=base64.b64encode(payload).decode(),
            signature_b64=base64.b64encode(sig).decode(),
        )
        first = self.admitter.admit(**kwargs)
        self.assertEqual(first.status, 201)
        replay = self.admitter.admit(**kwargs)
        self.assertTrue(replay.accepted)
        self.assertEqual(replay.status, 200)
        self.assertTrue(replay.duplicate)
        self.assertEqual(replay.record["activateAt"], future)
        # even after the scheduled time passed, retry writes no new record
        self.assertEqual(self.store.accepted_generations("dev"), [1])
        eff = self.admitter.effective("dev")
        self.assertEqual(eff["generation"], 1)
        self.assertEqual(eff["attestationId"], "a1")

    def test_omitted_activate_at_is_immediate_and_absent_from_response(self):
        d = self.submit("a1", "dev", 1, 0, b"cfg-1")
        self.assertTrue(d.accepted)
        self.assertIsNone(d.record["activateAt"])
        self.assertIsNotNone(self.admitter.effective("dev"))

    def test_concurrent_scheduled_competitors_keep_head_and_effective_consistent(self):
        past = utc_stamp(datetime.now(timezone.utc) - timedelta(hours=1))
        future = utc_stamp(datetime.now(timezone.utc) + timedelta(hours=1))
        self.assertTrue(
            self.submit("root", "dev", 1, 0, b"cfg-1", activate_at=past).accepted
        )
        results = []

        def worker(att_id, cfg):
            d = self.submit(att_id, "dev", 2, 1, cfg, activate_at=future)
            results.append((att_id, d.accepted, d.code))

        threads = [
            threading.Thread(target=worker, args=(f"sched-g2-{i}", f"cfg-{i}".encode()))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        wins = [r for r in results if r[1]]
        self.assertEqual(len(wins), 1, results)
        self.assertEqual(self.store.accepted_generations("dev"), [1, 2])
        # head advanced to gen 2, but the future schedule keeps gen 1 effective
        self.assertEqual(self.admitter.head("dev")["generation"], 2)
        self.assertEqual(self.admitter.effective("dev")["generation"], 1)

    def test_chain_of_scheduled_generations_with_gaps_in_time(self):
        t0 = datetime.now(timezone.utc).replace(microsecond=0)
        self.assertTrue(self.submit(
            "a1", "dev", 10, 0, b"cfg-1",
            activate_at=utc_stamp(t0 + timedelta(seconds=100))).accepted)
        d = self.submit(
            "a2", "dev", 11, 10, b"cfg-2",
            activate_at=utc_stamp(t0 + timedelta(seconds=100)))
        self.assertTrue(d.accepted, d.message)
        self.assertEqual(
            self.store.effective("dev", utc_stamp(t0 + timedelta(seconds=100))).generation,
            11,
        )


class PreUpgradeMigrationTests(unittest.TestCase):
    """Volumes written before scheduling existed migrate transparently."""

    def test_legacy_rows_take_effect_at_accepted_at(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = os.path.join(tmp.name, "old.db")

        # Hand-build a database with the original (pre-upgrade) schema.
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE attestations ("
            "device_id TEXT NOT NULL, generation INTEGER NOT NULL, "
            "previous_generation INTEGER NOT NULL, config_sha256 TEXT NOT NULL, "
            "attestation_id TEXT NOT NULL, payload_sha256 TEXT NOT NULL, "
            "accepted_at TEXT NOT NULL, PRIMARY KEY (device_id, generation), "
            "UNIQUE (attestation_id))"
        )
        conn.execute(
            "INSERT INTO attestations VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("legacy-dev", 1, 0, digest(b"old"), "legacy-1", "x" * 64,
             "2020-01-01T00:00:00Z"),
        )
        conn.commit()
        conn.close()

        store = Store(db_path)  # must migrate in place without losing data
        head = store.head("legacy-dev")
        self.assertEqual(head.generation, 1)
        self.assertIsNone(head.activate_at)

        # legacy rows are effective immediately (at their acceptedAt)
        eff = store.effective("legacy-dev", "2020-01-01T00:00:00Z")
        self.assertEqual(eff.generation, 1)
        eff_now = store.effective(
            "legacy-dev",
            utc_stamp(datetime.now(timezone.utc)),
        )
        self.assertEqual(eff_now.generation, 1)

        # new scheduled rows still work on the migrated database
        adm = Admitter(store, {KEY_ID: PUB}, {KEY_ID: None})
        future = utc_stamp(datetime.now(timezone.utc) + timedelta(hours=1))
        doc = {
            "deviceId": "legacy-dev",
            "generation": 2,
            "previousGeneration": 1,
            "configSha256": digest(b"new"),
            "activateAt": future,
        }
        payload = json.dumps(doc, separators=(",", ":")).encode()
        d = adm.admit(
            "new-1", KEY_ID,
            base64.b64encode(payload).decode(),
            base64.b64encode(ed25519.sign(payload, SEED)).decode(),
        )
        self.assertTrue(d.accepted, d.message)
        # while gen 2 is pending, the legacy gen 1 stays effective
        eff = store.effective("legacy-dev", utc_stamp(datetime.now(timezone.utc)))
        self.assertEqual(eff.generation, 1)


if __name__ == "__main__":
    unittest.main()
