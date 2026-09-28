"""Catalog-only tests: no asset downloads, traffic or experiment execution."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from check_release_assets import validate


class AssetCatalogTests(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads((ROOT / "evidence/RELEASE_ASSETS.json").read_text(encoding="utf-8-sig"))
        self.manifest = {"files": {item["relative_path"]: {
            "bytes": item["bytes"], "sha256": item["sha256"], "distribution": "companion_release_asset"
        } for item in self.catalog["assets"]}}
        # Keep tests valid after approved publication by explicitly using pending fixtures.
        self.catalog.update(release_status="not_published", release_page_url=None)
        for item in self.catalog["assets"]:
            item.update(download_url=None, publication_status="not_published")

    def test_local_preparation_is_not_publication(self):
        self.assertEqual(validate(self.catalog, self.manifest)["status"], "PREPARED_LINKS_PENDING")
        with self.assertRaises(ValueError):
            validate(self.catalog, self.manifest, require_published=True)

    def test_all_six_assets_required(self):
        self.catalog["assets"].pop()
        with self.assertRaises(ValueError):
            validate(self.catalog, self.manifest)

    def test_wrong_identity_rejected(self):
        self.catalog["assets"][0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            validate(self.catalog, self.manifest)

    def test_duplicate_path_rejected(self):
        self.catalog["assets"][1] = copy.deepcopy(self.catalog["assets"][0])
        with self.assertRaises(ValueError):
            validate(self.catalog, self.manifest)

    def test_published_claim_needs_links(self):
        self.catalog["assets"][0]["publication_status"] = "published"
        with self.assertRaises(ValueError):
            validate(self.catalog, self.manifest)

    def test_unsafe_link_rejected(self):
        self.catalog["assets"][0].update(download_url="http://example.org/archive.zip", publication_status="published")
        with self.assertRaises(ValueError):
            validate(self.catalog, self.manifest)

    def test_complete_link_fixture(self):
        self.catalog.update(release_status="published", release_page_url="https://example.org/release")
        for entry in self.catalog["assets"]:
            entry.update(download_url="https://example.org/" + entry["filename"], publication_status="published")
        self.assertEqual(validate(self.catalog, self.manifest, True)["status"], "CATALOG_VALID")


if __name__ == "__main__":
    unittest.main()
