"""Bounded extraction safety tests. No experiments, installs or network access."""

import importlib.util
import hashlib
import io
import json
import shutil
import stat
import unittest
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prepare_workspace", ROOT / "tools/prepare_workspace.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@contextmanager
def fresh_test_directory():
    # Use inherited permissions: restrictive 0700 temporary-directory ACLs can
    # exclude a sandboxed Windows process token even in its writable workspace.
    destination = ROOT.parent / ("test-prepare-" + uuid.uuid4().hex)
    destination.mkdir(exist_ok=False)
    try:
        yield destination
    finally:
        if destination.resolve().parent != ROOT.parent.resolve():
            raise RuntimeError("Refusing cleanup outside the test workspace")
        shutil.rmtree(destination)


def archive_with(names):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for item in names:
            archive.writestr(item, b"fixture")
    stream.seek(0)
    return zipfile.ZipFile(stream)


class PrepareWorkspaceTests(unittest.TestCase):
    def test_safe_regular_members(self):
        with archive_with(["root/src/main.py", "root/README.md"]) as archive:
            self.assertEqual(len(MODULE.validate_members(archive, "root/")), 2)

    def test_dangerous_paths(self):
        for name in ("root/../outside", "/root/file", "root/C:/ads", "root/file:ads", "root/a\\b", "root/CON", "root/nul.txt", "root/CONIN$", "root/x.", "root/x ", "root//x", "root/a//", "root/./x"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    MODULE.safe_relative(name)

    def test_duplicate_case_fold(self):
        with archive_with(["root/A.txt", "root/a.txt"]) as archive:
            with self.assertRaises(ValueError):
                MODULE.validate_members(archive, "root/")

    def test_directory_case_alias(self):
        with archive_with(["root/Foo/a.txt", "root/foo/b.txt"]) as archive:
            with self.assertRaises(ValueError):
                MODULE.validate_members(archive, "root/")

    def test_file_directory_collision(self):
        with archive_with(["root/a", "root/a/file"]) as archive:
            with self.assertRaises(ValueError):
                MODULE.validate_members(archive, "root/")

    def test_symlink_and_special_file(self):
        for kind in (stat.S_IFLNK, stat.S_IFIFO):
            item = zipfile.ZipInfo("root/link")
            item.create_system = 3
            item.external_attr = (kind | 0o777) << 16
            with self.subTest(kind=kind), archive_with([item]) as archive:
                with self.assertRaises(ValueError):
                    MODULE.validate_members(archive, "root/")

    def test_wrong_root(self):
        with archive_with(["unexpected/file"]) as archive:
            with self.assertRaises(ValueError):
                MODULE.validate_members(archive, "root/")

    def test_manifest_membership_required(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("root/file", b"fixture")
            archive.writestr("root/MANIFEST.json", json.dumps({"files": {}}))
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            members = MODULE.validate_members(archive, "root/")
            with self.assertRaises(ValueError):
                MODULE.verify_manifest(archive, members, "MANIFEST.json")

    def test_existing_destination_refused(self):
        with fresh_test_directory() as temporary:
            destination = Path(temporary) / "existing"
            destination.mkdir()
            with self.assertRaisesRegex(ValueError, "already exists"):
                MODULE.prepare("packet", destination)

    def test_inputs_must_be_paired(self):
        with self.assertRaisesRegex(ValueError, "Supply both"):
            MODULE.prepare("windows", Path("unused-destination"), Path("one-input"))

    def test_packet_rejects_dataset_flags(self):
        with self.assertRaisesRegex(ValueError, "only to the Windows"):
            MODULE.prepare("packet", Path("unused-destination"), Path("one"), Path("two"))

    def test_public_packet_preparation(self):
        with fresh_test_directory() as temporary:
            destination = Path(temporary) / "packet"
            receipt_path, receipt = MODULE.prepare("packet", destination)
            self.assertEqual(receipt["status"], "complete")
            self.assertEqual(receipt["source_manifest_file_count"], 154)
            self.assertFalse((destination / "docs/paper/closed_loop_experiment.tex").exists())
            self.assertTrue(receipt["public_packaging"]["scientific_source_bytes_preserved"])
            self.assertFalse(receipt["executed_code"])
            self.assertEqual(receipt_path.parent, destination.parent)
            self.assertFalse((destination / receipt_path.name).exists())
            self.assertEqual(len(list(destination.rglob("*.*"))) > 0, True)

    def test_public_snapshots_preserve_recorded_scientific_members(self):
        snapshot_dir = ROOT / "evidence/source_snapshots"
        record = json.loads((snapshot_dir / "PUBLIC_SOURCE_OMISSIONS.json").read_text(encoding="utf-8"))
        snapshots = {item["public_filename"]: item for item in record["source_snapshots"]}
        for spec in MODULE.SNAPSHOTS.values():
            item = snapshots[spec["name"]]
            with self.subTest(snapshot=spec["name"]), zipfile.ZipFile(snapshot_dir / spec["name"]) as archive:
                names = archive.namelist()
                self.assertNotIn(spec["prefix"] + "docs/paper/closed_loop_experiment.tex", names)
                metadata = json.loads(archive.read(spec["prefix"] + spec["manifest"]))
                self.assertEqual(metadata["public_packaging"]["original_archive_sha256"], spec["original_archive_sha256"])
                for name, expected in item["scientific_member_identities"].items():
                    data = archive.read(spec["prefix"] + name)
                    self.assertEqual({"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}, expected)
                for name in names:
                    if not name.endswith(".zip"):
                        continue
                    with zipfile.ZipFile(io.BytesIO(archive.read(name))) as nested:
                        self.assertFalse(any(member.endswith(".tex") for member in nested.namelist()))


if __name__ == "__main__":
    unittest.main()
