import sqlite3
import unittest

from backend.mitre import (
    SUBTECHNIQUES,
    TACTICS,
    TECHNIQUES,
    aggregate_discovery,
    attack_url,
    discovery_techniques,
    map_attack_to_mitre,
    resolve_mitre,
)


class MitreMappingTest(unittest.TestCase):
    def test_high_confidence_mappings(self):
        cases = {
            "Credential Attack": ("TA0006", "T1110", "T1110.001"),
            "Unauthorized Login": ("TA0001", "T1078", "T1078.003"),
            "Post-Login Activity": ("TA0002", "T1059", "T1059.004"),
            "Malware Upload": ("TA0011", "T1105", None),
            "SQL Injection": ("TA0001", "T1190", None),
        }
        for attack_type, (tactic, technique, sub) in cases.items():
            result = map_attack_to_mitre(attack_type, {})
            self.assertEqual(result["mitre_tactic"], tactic, attack_type)
            self.assertEqual(result["mitre_technique"], technique, attack_type)
            self.assertEqual(result["mitre_subtechnique"], sub, attack_type)
            self.assertEqual(result["mitre_confidence"], "Alto", attack_type)

    def test_command_injection_subtechnique_only_for_shell_sources(self):
        shell = map_attack_to_mitre("Command Injection", {"source": "cowrie"})
        self.assertEqual(shell["mitre_subtechnique"], "T1059.004")
        self.assertEqual(shell["mitre_confidence"], "Alto")

        web = map_attack_to_mitre("Command Injection", {"source": "opencanary"})
        self.assertEqual(web["mitre_technique"], "T1059")
        self.assertIsNone(web["mitre_subtechnique"])
        self.assertEqual(web["mitre_confidence"], "Medio")

    def test_recon_subtechnique_heuristic(self):
        vuln = map_attack_to_mitre("Web Crawl / Recon", {"user_agent": "Nikto/2.5"})
        self.assertEqual(vuln["mitre_subtechnique"], "T1595.002")
        self.assertEqual(vuln["mitre_confidence"], "Alto")

        wordlist = map_attack_to_mitre("Web Crawl / Recon", {"user_agent": "gobuster/3.6"})
        self.assertEqual(wordlist["mitre_subtechnique"], "T1595.003")

        plain = map_attack_to_mitre("Web Crawl / Recon", {"user_agent": "Mozilla/5.0"})
        self.assertEqual(plain["mitre_technique"], "T1595")
        self.assertIsNone(plain["mitre_subtechnique"])
        self.assertEqual(plain["mitre_confidence"], "Medio")

    def test_ftp_direction_refinement(self):
        upload = map_attack_to_mitre("FTP Attack", {"command": "STOR"})
        self.assertEqual(upload["mitre_technique"], "T1105")
        self.assertEqual(upload["mitre_confidence"], "Medio")

        # RETR/DELE: intento ambiguo -> non classificato, niente ID forzato.
        download = map_attack_to_mitre("FTP Attack", {"command": "RETR"})
        self.assertIsNone(download["mitre_technique"])
        self.assertIsNone(download["mitre_confidence"])

    def test_weak_mappings_are_low_confidence(self):
        for attack_type, technique in [
            ("IDOR Attempt", "T1190"),
            ("XSS Attack", "T1190"),
            ("SMB Attack", "T1210"),
        ]:
            result = map_attack_to_mitre(attack_type, {})
            self.assertEqual(result["mitre_technique"], technique, attack_type)
            self.assertEqual(result["mitre_confidence"], "Basso", attack_type)

    def test_unknown_and_empty_are_not_classified(self):
        for attack_type in ["Unknown", "", None, "Categoria Inesistente"]:
            result = map_attack_to_mitre(attack_type, {})
            self.assertIsNone(result["mitre_technique"])
            self.assertIsNone(result["mitre_tactic"])

    def test_no_invented_ids(self):
        """Ogni ID emesso deve esistere nel riferimento vendorizzato."""
        attack_types = [
            "Credential Attack", "Unauthorized Login", "Post-Login Activity",
            "Command Injection", "Malware Upload", "SQL Injection",
            "Web Crawl / Recon", "Port Scan", "FTP Attack", "IDOR Attempt",
            "XSS Attack", "SMB Attack",
        ]
        records = [{}, {"source": "cowrie"}, {"command": "STOR"}, {"user_agent": "nmap"}]
        for attack_type in attack_types:
            for record in records:
                result = map_attack_to_mitre(attack_type, record)
                if result["mitre_tactic"]:
                    self.assertIn(result["mitre_tactic"], TACTICS)
                if result["mitre_technique"]:
                    self.assertIn(result["mitre_technique"], TECHNIQUES)
                if result["mitre_subtechnique"]:
                    self.assertIn(result["mitre_subtechnique"], SUBTECHNIQUES)


class MitreResolveTest(unittest.TestCase):
    def test_resolve_adds_names_and_url(self):
        resolved = resolve_mitre("TA0006", "T1110", "T1110.001", "Alto")
        self.assertEqual(resolved["mitre_tactic_name"], "Credential Access")
        self.assertEqual(resolved["mitre_technique_name"], "Brute Force")
        self.assertEqual(resolved["mitre_subtechnique_name"], "Password Guessing")
        self.assertEqual(resolved["mitre_url"], "https://attack.mitre.org/techniques/T1110/001/")
        self.assertFalse(resolved["mitre_uncertain"])

    def test_uncertain_flag_for_low_confidence(self):
        resolved = resolve_mitre("TA0001", "T1190", None, "Basso")
        self.assertTrue(resolved["mitre_uncertain"])
        self.assertEqual(resolved["mitre_url"], "https://attack.mitre.org/techniques/T1190/")

    def test_resolve_empty_is_all_none(self):
        resolved = resolve_mitre(None, None, None, None)
        self.assertIsNone(resolved["mitre_technique_name"])
        self.assertIsNone(resolved["mitre_url"])
        self.assertFalse(resolved["mitre_uncertain"])

    def test_attack_url_forms(self):
        self.assertEqual(attack_url("T1059", None), "https://attack.mitre.org/techniques/T1059/")
        self.assertEqual(attack_url("T1059", "T1059.004"), "https://attack.mitre.org/techniques/T1059/004/")
        self.assertIsNone(attack_url(None, None))


class DiscoveryTechniquesTest(unittest.TestCase):
    def _ids(self, command):
        return [entry["id"] for entry in discovery_techniques(command)]

    def test_known_commands_map_to_correct_technique(self):
        cases = {
            "whoami": "T1033",
            "id": "T1033",
            "uname -a": "T1082",
            "cat /proc/cpuinfo": "T1082",
            "ps aux": "T1057",
            "netstat -an": "T1049",
            "ifconfig": "T1016",
            "ip a": "T1016",
            "cat /etc/passwd": "T1087.001",
            "groups": "T1069.001",
            "which python": "T1518",
        }
        for command, technique in cases.items():
            self.assertIn(technique, self._ids(command), command)

    def test_command_with_path_prefix_and_pipes(self):
        self.assertEqual(self._ids("/usr/bin/whoami"), ["T1033"])
        # un comando concatenato puo rivelare piu technique distinte
        ids = self._ids("uname -a; cat /etc/passwd")
        self.assertIn("T1082", ids)
        self.assertIn("T1087.001", ids)

    def test_shadow_is_not_discovery(self):
        # /etc/shadow e Credential Access (T1003), fuori dallo scope Discovery.
        self.assertEqual(discovery_techniques("cat /etc/shadow"), [])

    def test_noise_and_empty_map_to_nothing(self):
        for command in ["sdaf", "das", "", None, "exit", "clear"]:
            self.assertEqual(discovery_techniques(command), [])

    def test_high_volume_commands_are_medium_confidence(self):
        entry = discovery_techniques("ls -la")[0]
        self.assertEqual(entry["id"], "T1083")
        self.assertEqual(entry["confidence"], "Medio")

    def test_emitted_ids_exist_in_reference(self):
        commands = ["whoami", "uname", "cat /etc/passwd", "groups", "netstat",
                    "ps", "ifconfig", "ls", "which", "cat /etc/hosts", "date"]
        for command in commands:
            for entry in discovery_techniques(command):
                self.assertEqual(entry["tactic"], "TA0007")
                self.assertIn(entry["technique"], TECHNIQUES)
                if entry["subtechnique"]:
                    self.assertIn(entry["subtechnique"], SUBTECHNIQUES)

    def test_aggregate_counts_and_keeps_highest_confidence(self):
        commands = ["whoami", "whoami", "ls", "uname -a", "sdaf", "cat /etc/passwd"]
        agg = {item["id"]: item for item in aggregate_discovery(commands)}
        self.assertEqual(agg["T1033"]["count"], 2)
        self.assertEqual(agg["T1083"]["count"], 1)
        self.assertIn("T1082", agg)
        self.assertIn("T1087.001", agg)
        # ordinamento per frequenza decrescente
        ordered = aggregate_discovery(commands)
        self.assertEqual(ordered[0]["id"], "T1033")


class MitreMigrationTest(unittest.TestCase):
    def test_migration_adds_missing_columns_idempotently(self):
        from backend.db import _migrate_events

        conn = sqlite3.connect(":memory:")
        # Schema "vecchio": tabella events senza colonne MITRE.
        conn.execute('CREATE TABLE events (id INTEGER PRIMARY KEY, attack_type TEXT)')
        conn.execute("INSERT INTO events (attack_type) VALUES ('SQL Injection')")

        _migrate_events(conn)
        columns = {row[1] for row in conn.execute('PRAGMA table_info(events)').fetchall()}
        for col in ("mitre_tactic", "mitre_technique", "mitre_subtechnique", "mitre_confidence"):
            self.assertIn(col, columns)

        # La riga storica sopravvive con valori NULL.
        row = conn.execute('SELECT attack_type, mitre_technique FROM events').fetchone()
        self.assertEqual(row[0], "SQL Injection")
        self.assertIsNone(row[1])

        # Idempotente: una seconda esecuzione non solleva eccezioni.
        _migrate_events(conn)
        conn.close()


if __name__ == "__main__":
    unittest.main()
