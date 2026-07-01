import importlib
import os
import tempfile
import unittest
from pathlib import Path


class TriageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old_env = os.environ.copy()
        os.environ.update({
            "HPX_DB_PATH": str(self.root / "honeypotx.db"),
        })

        import backend.config as config
        import backend.db as db

        self.config = importlib.reload(config)
        self.db = importlib.reload(db)
        self.db.init_db()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.old_env)
        self.tmp.cleanup()

    def _insert(self, event_hash, ip="192.0.2.1", attack_type="Unauthorized Login", danger_level="Alto", country="Italy"):
        self.db.insert_event({
            "event_hash": event_hash,
            "ip": ip,
            "attack_type": attack_type,
            "danger_level": danger_level,
            "country": country,
        })

    def test_new_event_defaults_to_true_positive(self):
        self._insert("h1")
        event = self.db.fetch_events()[0]
        self.assertEqual(event["triage_status"], "true_positive")

    def test_false_positive_is_hidden_from_default_list_and_stats(self):
        self._insert("h1")
        event_id = self.db.fetch_events()[0]["id"]

        updated = self.db.set_event_triage(event_id, "false_positive")
        self.assertEqual(updated["triage_status"], "false_positive")

        self.assertEqual(self.db.fetch_events(), [])
        self.assertEqual(self.db.fetch_stats()["total"], 0)
        self.assertEqual(self.db.fetch_attack_distribution(), [])

    def test_authorized_activity_is_hidden_too(self):
        self._insert("h1")
        event_id = self.db.fetch_events()[0]["id"]
        self.db.set_event_triage(event_id, "authorized_activity")
        self.assertEqual(self.db.fetch_events(), [])

    def test_triaged_out_filter_shows_only_derubricated_events(self):
        self._insert("h1")
        self._insert("h2")
        events = self.db.fetch_events(triage="all")
        self.db.set_event_triage(events[0]["id"], "false_positive")
        self.db.set_event_triage(events[1]["id"], "authorized_activity")

        # tutti derubricati: la vista di default (true_positive) e' vuota
        self.assertEqual(self.db.fetch_events(), [])
        # ma restano consultabili tramite il filtro dedicato
        triaged_out = self.db.fetch_events(triage="triaged_out")
        self.assertEqual(len(triaged_out), 2)
        statuses = {e["triage_status"] for e in triaged_out}
        self.assertEqual(statuses, {"false_positive", "authorized_activity"})

    def test_all_filter_ignores_triage_status(self):
        self._insert("h1")
        event_id = self.db.fetch_events()[0]["id"]
        self.db.set_event_triage(event_id, "false_positive")
        self.assertEqual(len(self.db.fetch_events(triage="all")), 1)

    def test_reverting_to_true_positive_restores_visibility(self):
        self._insert("h1")
        event_id = self.db.fetch_events()[0]["id"]
        self.db.set_event_triage(event_id, "false_positive")
        self.assertEqual(self.db.fetch_events(), [])

        self.db.set_event_triage(event_id, "true_positive")
        self.assertEqual(len(self.db.fetch_events()), 1)

    def test_set_event_triage_rejects_invalid_status(self):
        self._insert("h1")
        event_id = self.db.fetch_events()[0]["id"]
        with self.assertRaises(ValueError):
            self.db.set_event_triage(event_id, "not-a-real-status")

    def test_set_event_triage_returns_none_for_missing_event(self):
        self.assertIsNone(self.db.set_event_triage(9999, "false_positive"))

    def test_set_ip_triage_bulk_updates_all_events_for_ip(self):
        self._insert("h1", ip="203.0.113.5")
        self._insert("h2", ip="203.0.113.5")
        self._insert("h3", ip="203.0.113.9")

        updated = self.db.set_ip_triage("203.0.113.5", "false_positive")
        self.assertEqual(updated, 2)

        remaining = self.db.fetch_events()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["ip"], "203.0.113.9")

    def test_set_ip_triage_returns_zero_for_unknown_ip(self):
        self.assertEqual(self.db.set_ip_triage("198.51.100.1", "false_positive"), 0)

    def test_fetch_event_by_id_ignores_triage_status(self):
        # la modale di dettaglio deve funzionare anche su eventi derubricati,
        # per permettere di rivederli/ripristinarli.
        self._insert("h1")
        event_id = self.db.fetch_events()[0]["id"]
        self.db.set_event_triage(event_id, "false_positive")
        self.assertIsNotNone(self.db.fetch_event_by_id(event_id))


if __name__ == "__main__":
    unittest.main()
