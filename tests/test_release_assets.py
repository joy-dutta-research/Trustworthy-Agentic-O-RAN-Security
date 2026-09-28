"""Catalog-only tests: no asset downloads, traffic or experiment execution."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from check_release_assets import validate
import check_release_assets as assets


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

    def test_command_reads_relocated_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "RELEASE_ASSETS.json").write_text(json.dumps(self.catalog), encoding="utf-8")
            manifest_path = root / assets.MANIFEST_NAME
            self.assertEqual(manifest_path.parent, root / "release")
            manifest_path.parent.mkdir()
            manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
            guide = []
            for entry in self.catalog["assets"]:
                guide.extend(["## " + entry["regeneration"]["guide_anchor"], entry["filename"]])
                sidecar = root / (entry["relative_path"] + ".sha256")
                sidecar.parent.mkdir(parents=True, exist_ok=True)
                sidecar.write_text(entry["sha256"] + "  " + entry["filename"] + "\n", encoding="ascii")
            (root / self.catalog["guide_path"]).write_text("\n\n".join(guide), encoding="utf-8")
            output = io.StringIO()
            with patch.object(assets, "ROOT", root), patch.object(sys, "argv", ["check_release_assets.py"]), redirect_stdout(output):
                self.assertEqual(assets.main(), 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "PREPARED_LINKS_PENDING")


if __name__ == "__main__":
    unittest.main()
