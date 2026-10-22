import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prepare_agh", ROOT / "tools/prepare_agh_config.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
PROFILES = json.loads((ROOT / "examples/adguardhome/clients.json").read_text(encoding="utf-8"))
TEMP_ROOT = ROOT / ".agents/runs/agh-config-tests"


def fixture():
    return {
        "dns": {"bind_hosts": ["127.0.0.1"], "port": 5591, "upstream_dns": ["https://223.5.5.5/dns-query"]},
        "users": [{"name": "fixture", "password": "fixture-hash"}],
        "filters": [{"id": 2026102101, "enabled": True}],
        "user_rules": ["@@||fixture.example^$important"],
        "clients": {"persistent": [{"name": "existing", "ids": ["192.0.2.1"]}]},
    }


class AGHConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TEMP_ROOT.mkdir(parents=True, exist_ok=True)

    def test_preserves_rules_credentials_and_global_upstreams(self):
        original = fixture()
        candidate = MODULE.merge_profile(original, PROFILES)
        for key in ("dns", "users", "filters", "user_rules"):
            self.assertEqual(candidate[key], original[key])
        self.assertEqual(candidate["clients"]["persistent"][0], original["clients"]["persistent"][0])
        self.assertEqual(original, fixture())

    def test_idempotent_and_separate_filtered_caches(self):
        once = MODULE.merge_profile(fixture(), PROFILES)
        self.assertEqual(MODULE.merge_profile(once, PROFILES), once)
        for profile in once["clients"]["persistent"][1:]:
            self.assertTrue(profile["use_global_settings"])
            self.assertTrue(profile["upstreams_cache_enabled"])
            self.assertGreater(profile["upstreams_cache_size"], 0)
        self.assertNotEqual(PROFILES[0]["ids"], PROFILES[1]["ids"])

    def test_existing_ip_or_covering_subnet_is_rejected(self):
        for identifier in ("127.0.0.2", "127.0.0.0/8", "127.0.0.3/32"):
            with self.subTest(identifier=identifier):
                config = fixture()
                config["clients"]["persistent"][0]["ids"] = [identifier]
                with self.assertRaises(ValueError):
                    MODULE.merge_profile(config, PROFILES)

    def test_same_name_with_different_identity_is_rejected(self):
        config = fixture()
        config["clients"]["persistent"][0]["name"] = PROFILES[0]["name"]
        with self.assertRaises(ValueError):
            MODULE.merge_profile(config, PROFILES)

    def test_access_control_is_respected(self):
        for options in ({"allowed_clients": ["192.0.2.0/24"]}, {"disallowed_clients": ["127.0.0.0/8"]}):
            config = fixture()
            config["dns"].update(options)
            with self.assertRaises(ValueError):
                MODULE.merge_profile(config, PROFILES)
        config = fixture()
        config["dns"]["allowed_clients"] = ["127.0.0.0/8"]
        MODULE.merge_profile(config, PROFILES)

    def test_incompatible_listener_or_disabled_filter_is_rejected(self):
        changes = [("dns", "port", 53), ("dns", "bind_hosts", ["::1"]), ("dns", "serve_plain_dns", False),
                   ("filtering", "protection_enabled", False), ("filtering", "filtering_enabled", False)]
        for section, key, value in changes:
            config = fixture()
            config.setdefault(section, {})[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                MODULE.merge_profile(config, PROFILES)

    def test_output_is_exclusive_and_input_never_changes(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            self.assertEqual(Path(directory).resolve().parent, TEMP_ROOT.resolve())
            source, target = Path(directory) / "input.yaml", Path(directory) / "candidate.yaml"
            original = yaml.safe_dump(fixture())
            source.write_text(original, encoding="utf-8")
            MODULE.prepare(source, target)
            self.assertEqual(source.read_text(encoding="utf-8"), original)
            self.assertEqual(yaml.safe_load(target.read_text()), MODULE.merge_profile(fixture(), PROFILES))
            with self.assertRaises(FileExistsError):
                MODULE.prepare(source, target)
            with self.assertRaises(ValueError):
                MODULE.prepare(source, source)

    def test_duplicate_yaml_keys_are_rejected_before_output(self):
        with tempfile.TemporaryDirectory(dir=TEMP_ROOT) as directory:
            self.assertEqual(Path(directory).resolve().parent, TEMP_ROOT.resolve())
            source, target = Path(directory) / "input.yaml", Path(directory) / "candidate.yaml"
            source.write_text("dns: {}\ndns: {}\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.prepare(source, target)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
