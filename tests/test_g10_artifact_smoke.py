import json
from pathlib import Path
import tempfile
import unittest

from tools.g10_artifact_smoke import assign_isolated_gateway_ports


class G10ArtifactSmokeTests(unittest.TestCase):
    def test_assigns_distinct_loopback_ports_without_changing_other_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "active.json"
            original = {
                "schema_version": 1,
                "listen": {
                    "host": "127.0.0.1",
                    "data_port": 18766,
                    "control_port": 18767,
                },
                "active_group": {"revision": 1},
            }
            config_path.write_text(json.dumps(original), encoding="utf-8")

            data_port, control_port = assign_isolated_gateway_ports(config_path)
            updated = json.loads(config_path.read_text(encoding="utf-8"))

            self.assertNotEqual(data_port, control_port)
            self.assertEqual(updated["listen"]["host"], "127.0.0.1")
            self.assertEqual(updated["listen"]["data_port"], data_port)
            self.assertEqual(updated["listen"]["control_port"], control_port)
            self.assertEqual(updated["active_group"], original["active_group"])


if __name__ == "__main__":
    unittest.main()
