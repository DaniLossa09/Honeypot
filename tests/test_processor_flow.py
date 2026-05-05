import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class ProcessorFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cowrie_log = self.root / "cowrie.json"
        self.opencanary_log = self.root / "opencanary.log"
        self.ftp_log = self.root / "ftp.json"
        self.db_path = self.root / "honeypotx.db"
        self.offsets_path = self.root / "offsets.json"
        self.export_path = self.root / "events_export.json"
        self.geo_cache_path = self.root / "geo_cache.json"

        for path in (self.cowrie_log, self.opencanary_log, self.ftp_log):
            path.write_text("", encoding="utf-8")

        self.old_env = os.environ.copy()
        os.environ.update({
            "HPX_COWRIE_LOG": str(self.cowrie_log),
            "HPX_OPENCANARY_LOG": str(self.opencanary_log),
            "HPX_FTP_LOG": str(self.ftp_log),
            "HPX_DB_PATH": str(self.db_path),
            "HPX_OFFSETS_PATH": str(self.offsets_path),
            "HPX_EVENTS_EXPORT_PATH": str(self.export_path),
            "HPX_GEO_CACHE_PATH": str(self.geo_cache_path),
        })

        import backend.config as config
        import backend.db as db
        import backend.geolocation as geolocation
        import backend.processor as processor

        self.config = importlib.reload(config)
        self.db = importlib.reload(db)
        importlib.reload(geolocation)
        self.processor_module = importlib.reload(processor)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.old_env)
        self.tmp.cleanup()

    def _processor(self):
        class FakeGeoResolver:
            def resolve(self, ip):
                return {"country": "Test", "city": "Test", "lat": None, "lon": None}

        with patch.object(self.processor_module, "GeoResolver", FakeGeoResolver):
            return self.processor_module.Processor()

    def _append_json(self, path, obj):
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj) + "\n")

    def test_process_once_raises_credential_incidents_only_after_threshold(self):
        processor = self._processor()

        for minute in range(2):
            self._append_json(self.cowrie_log, {
                "eventid": "cowrie.login.failed",
                "username": "root",
                "password": f"bad-{minute}",
                "src_ip": "192.0.2.10",
                "timestamp": f"2026-04-29T18:0{minute}:00Z",
                "protocol": "ssh",
            })
        self._append_json(self.opencanary_log, {
            "dst_port": 80,
            "logtype": 3001,
            "src_host": "192.0.2.20",
            "local_time": "2026-04-29T18:00:00Z",
            "logdata": {"PATH": "/login", "USERNAME": "client", "PASSWORD": "secret"},
        })
        self._append_json(self.ftp_log, {
            "timestamp": "2026-04-29T18:00:00Z",
            "src_ip": "192.0.2.30",
            "command": "PASS",
            "argument": "secret",
        })

        self.assertEqual(processor.process_once(), 0)
        self.assertEqual(self.db.fetch_events(), [])

        self._append_json(self.cowrie_log, {
            "eventid": "cowrie.login.failed",
            "username": "root",
            "password": "bad-2",
            "src_ip": "192.0.2.10",
            "timestamp": "2026-04-29T18:02:00Z",
            "protocol": "ssh",
        })
        for minute in range(1, 3):
            self._append_json(self.opencanary_log, {
                "dst_port": 80,
                "logtype": 3001,
                "src_host": "192.0.2.20",
                "local_time": f"2026-04-29T18:0{minute}:00Z",
                "logdata": {"PATH": "/login", "USERNAME": "client", "PASSWORD": f"secret-{minute}"},
            })
            self._append_json(self.ftp_log, {
                "timestamp": f"2026-04-29T18:0{minute}:00Z",
                "src_ip": "192.0.2.30",
                "command": "PASS",
                "argument": f"secret-{minute}",
            })

        self.assertEqual(processor.process_once(), 3)
        events = self.db.fetch_events()
        self.assertEqual(len(events), 3)
        self.assertEqual({event["attack_type"] for event in events}, {"Credential Attack"})
        self.assertEqual({event["source"] for event in events}, {"cowrie", "opencanary", "ftp"})

    def test_opencanary_credential_threshold_groups_different_usernames_by_ip(self):
        processor = self._processor()

        for minute, username in enumerate(["alice", "bob", "charlie"]):
            self._append_json(self.opencanary_log, {
                "dst_port": 80,
                "logtype": 3001,
                "src_host": "192.0.2.50",
                "local_time": f"2026-04-29T18:0{minute}:00Z",
                "logdata": {
                    "PATH": "/index.html",
                    "USERNAME": username,
                    "PASSWORD": f"secret-{minute}",
                },
            })

        self.assertEqual(processor.process_once(), 1)
        events = self.db.fetch_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "opencanary")
        self.assertEqual(events[0]["ip"], "192.0.2.50")
        self.assertEqual(events[0]["attack_type"], "Credential Attack")
        context = self.db.fetch_event_context(events[0]["id"])
        self.assertIsNotNone(context)
        self.assertEqual(len(context["raw_events"]), 3)
        self.assertEqual(
            [item["username"] for item in context["raw_events"]],
            ["alice", "bob", "charlie"],
        )

        self._processor()
        events_after_reconcile = self.db.fetch_events()
        self.assertEqual(len(events_after_reconcile), 1)
        self.assertEqual(events_after_reconcile[0]["attack_type"], "Credential Attack")

    def test_process_once_deduplicates_post_login_commands_by_session(self):
        processor = self._processor()
        base = {
            "src_ip": "192.0.2.40",
            "timestamp": "2026-04-29T18:00:00Z",
            "protocol": "ssh",
            "session": "session-1",
        }
        self._append_json(self.cowrie_log, {
            **base,
            "eventid": "cowrie.login.success",
            "username": "admin",
            "password": "password",
        })
        self._append_json(self.cowrie_log, {
            **base,
            "eventid": "cowrie.command.input",
            "input": "whoami",
        })
        self._append_json(self.cowrie_log, {
            **base,
            "eventid": "cowrie.command.input",
            "input": "uname -a",
        })

        self.assertEqual(processor.process_once(), 2)
        events = self.db.fetch_events()
        self.assertEqual(len(events), 2)
        self.assertEqual(
            {event["attack_type"] for event in events},
            {"Unauthorized Login", "Post-Login Activity"},
        )

        storylines = self.db.fetch_storylines()
        self.assertEqual(len(storylines), 1)
        self.assertEqual(storylines[0]["title"], "Compromissione interattiva SSH")
        self.assertEqual(storylines[0]["event_count"], 2)
        self.assertEqual(
            [event["attack_type"] for event in storylines[0]["events"]],
            ["Unauthorized Login", "Post-Login Activity"],
        )

        post_login = next(event for event in events if event["attack_type"] == "Post-Login Activity")
        context = self.db.fetch_event_context(post_login["id"])
        self.assertIsNotNone(context)
        self.assertEqual(
            [item["command"] for item in context["raw_events"] if item["command"]],
            ["whoami", "uname -a"],
        )


if __name__ == "__main__":
    unittest.main()
