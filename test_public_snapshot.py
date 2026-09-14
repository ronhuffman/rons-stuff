"""Offline snapshot checks; no appliance/network access or HA runtime validation."""
import json
from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parent
HA = ROOT / "shared-and-home-assistant" / "home-assistant"


class StrictLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate YAML key: " + str(key))
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
StrictLoader.add_constructor("!secret", lambda loader, node: {"secret_reference": loader.construct_scalar(node)})


def read_yaml(name):
    return yaml.load((HA / name).read_text(encoding="utf-8"), Loader=StrictLoader)


class SnapshotTests(unittest.TestCase):
    def test_initial_slots_and_public_build_labels(self):
        for device in ("washer", "dryer"):
            folder = ROOT / device
            source = (folder / (device + "_a.py")).read_bytes()
            self.assertEqual(source, (folder / (device + "_b.py")).read_bytes())
            self.assertRegex(source, rb'BUILD = "[^"\r\n]+-public-example"')

    def test_example_configs_are_placeholders_not_deployment_files(self):
        for device in ("washer", "dryer"):
            folder = ROOT / device
            config = json.loads((folder / "pico_config.example.json").read_text())
            self.assertEqual(config["WIFI_SSID"], "REPLACE_ME")
            self.assertEqual(config["WIFI_PASSWORD"], "REPLACE_ME")
            self.assertLess(len(config["UPDATE_TOKEN"]), 32)
            self.assertFalse((folder / "pico_config.json").exists(), "Do not put deployment secrets in this public snapshot.")

    def test_package_references_and_expected_definitions(self):
        package = read_yaml("laundry-package.example.yaml")
        secrets = read_yaml("secrets.example.yaml")
        self.assertEqual(set(package), {"sensor", "template", "rest_command"})
        self.assertEqual(len(package["sensor"]), 2)
        refs = [item["resource"]["secret_reference"] for item in package["sensor"]]
        refs.append(package["rest_command"]["washer_acknowledge"]["url"]["secret_reference"])
        self.assertEqual(set(refs), set(secrets))
        for url in secrets.values():
            self.assertRegex(url, r"^http://192\.0\.2\.(10|20)/(status|ack)$")
        ids = [item["unique_id"] for item in package["sensor"]]
        templates = [item for group in package["template"] for items in group.values() for item in items]
        self.assertEqual(len(templates), 15)
        ids.extend(item["unique_id"] for item in templates)
        self.assertEqual(len(ids), len(set(ids)))

    def test_dashboard_dependencies_are_defined_or_explicit_shelly_placeholders(self):
        package = read_yaml("laundry-package.example.yaml")
        dashboard = read_yaml("dashboard.example.yaml")
        expected = {"sensor.washer_state", "sensor.utility_room_pico"}
        for group in package["template"]:
            for domain, items in group.items():
                for item in items:
                    expected.add(domain + "." + re.sub(r"[^a-z0-9]+", "_", item["name"].lower()).strip("_"))
        expected.update("sensor.washer_plug_" + name for name in ("current", "power", "voltage", "temperature"))
        self.assertEqual(len(dashboard["views"][0]["sections"]), 3)
        for view in dashboard["views"]:
            for section in view["sections"]:
                for card in section["cards"]:
                    if "entity" in card:
                        self.assertIn(card["entity"], expected)

    def test_relative_document_links_resolve(self):
        for doc in ROOT.rglob("*.md"):
            for target in re.findall(r"\]\(([^)]+)\)", doc.read_text(encoding="utf-8")):
                if "://" in target or target.startswith("#"):
                    continue
                self.assertTrue((doc.parent / target.split("#")[0]).exists(), str(doc.relative_to(ROOT)) + ": " + target)


if __name__ == "__main__":
    unittest.main()
