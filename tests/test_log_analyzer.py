import unittest

from log_analyzer import analyze, parse_line


class ParseLineTests(unittest.TestCase):
    def test_parses_invalid_user_ssh_failure(self):
        line = (
            "Sep 24 09:12:01 lab sshd[1201]: Failed password for invalid user "
            "admin from 203.0.113.42 port 51122 ssh2"
        )

        event = parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "ssh_failed")
        self.assertEqual(event.user, "admin")
        self.assertEqual(event.source_ip, "203.0.113.42")

    def test_ignores_unsupported_line(self):
        self.assertIsNone(parse_line("Sep 24 09:00:00 lab cron: routine task"))


class AnalyzeTests(unittest.TestCase):
    def test_flags_repeated_failures_at_threshold(self):
        lines = [
            f"Sep 24 09:12:0{i} lab sshd[12{i}]: Failed password for root "
            "from 203.0.113.42 port 51122 ssh2"
            for i in range(3)
        ]

        summary = analyze(lines, threshold=3)

        self.assertEqual(summary["event_counts"]["ssh_failed"], 3)
        self.assertEqual(
            summary["brute_force_alerts"],
            [{"source_ip": "203.0.113.42", "failures": 3}],
        )

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=0)


if __name__ == "__main__":
    unittest.main()
