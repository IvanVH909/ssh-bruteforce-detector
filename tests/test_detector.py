import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detector import analyze, build_report  # noqa: E402

YEAR = 2024


def make_failed(sec, ip, user="root", invalid=False):
    inv = "invalid user " if invalid else ""
    return f"Dec 10 06:00:{sec:02d} host sshd[100]: Failed password for {inv}{user} from {ip} port 5000 ssh2"


class DetectorTests(unittest.TestCase):
    def test_cuenta_fallos_por_ip(self):
        lines = [make_failed(i, "1.2.3.4") for i in range(12)] + [make_failed(30, "5.6.7.8")]
        stats, meta = analyze(lines, YEAR)
        self.assertEqual(stats["1.2.3.4"].failures, 12)
        self.assertEqual(stats["5.6.7.8"].failures, 1)
        self.assertEqual(meta["failed_events"], 13)

    def test_usuario_invalido_se_registra(self):
        stats, _ = analyze([make_failed(1, "1.2.3.4", user="webmaster", invalid=True)], YEAR)
        self.assertEqual(stats["1.2.3.4"].invalid_user_attempts, 1)
        self.assertIn("webmaster", stats["1.2.3.4"].users)

    def test_message_repeated_suma_las_repeticiones(self):
        line = ("Dec 10 06:00:01 host sshd[100]: message repeated 5 times: "
                "[ Failed password for root from 1.2.3.4 port 5000 ssh2]")
        stats, meta = analyze([line], YEAR)
        self.assertEqual(stats["1.2.3.4"].failures, 5)
        self.assertEqual(meta["failed_events"], 5)

    def test_detecta_acceso_tras_fuerza_bruta(self):
        lines = [make_failed(i, "1.2.3.4") for i in range(15)]
        lines.append("Dec 10 06:01:00 host sshd[100]: Accepted password for root from 1.2.3.4 port 5000 ssh2")
        stats, _ = analyze(lines, YEAR)
        hits = stats["1.2.3.4"].compromised(threshold=10)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][1], "root")

    def test_no_marca_acceso_legitimo(self):
        lines = [make_failed(1, "9.9.9.9", user="ana"),
                 "Dec 10 06:01:00 host sshd[100]: Accepted password for ana from 9.9.9.9 port 5000 ssh2"]
        stats, _ = analyze(lines, YEAR)
        self.assertEqual(stats["9.9.9.9"].compromised(threshold=10), [])

    def test_exito_ANTES_de_los_fallos_no_cuenta(self):
        lines = ["Dec 10 06:00:00 host sshd[100]: Accepted password for ana from 9.9.9.9 port 5000 ssh2"]
        lines += [make_failed(10 + i, "9.9.9.9", user="ana") for i in range(15)]
        stats, _ = analyze(lines, YEAR)
        self.assertEqual(stats["9.9.9.9"].compromised(threshold=10), [])

    def test_clasificacion_spraying(self):
        lines = [make_failed(i, "1.2.3.4", user=f"user{i}") for i in range(8)]
        stats, _ = analyze(lines, YEAR)
        self.assertIn("spraying", stats["1.2.3.4"].attack_type)

    def test_informe_contiene_ip(self):
        lines = [make_failed(i, "1.2.3.4") for i in range(12)]
        stats, meta = analyze(lines, YEAR)
        self.assertIn("1.2.3.4", build_report(stats, meta, 10, "x.log"))


if __name__ == "__main__":
    unittest.main()
