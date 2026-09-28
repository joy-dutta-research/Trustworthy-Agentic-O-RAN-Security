"""Small in-memory fixtures for nested publication-file exclusion checks."""
import io
from pathlib import Path
import sys
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from check_publication_scope import inspect_zip


def zip_bytes(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return stream.getvalue()


class PublicationScopeTests(unittest.TestCase):
    def test_code_and_results_allowed(self):
        with zipfile.ZipFile(io.BytesIO(zip_bytes([("script.py", b"pass"), ("results.json", b"{}")])) ) as archive:
            found, count = inspect_zip(archive, "example.zip")
        self.assertEqual(found, [])
        self.assertEqual(count, 2)

    def test_publication_formats_reported(self):
        with zipfile.ZipFile(io.BytesIO(zip_bytes([("paper.TEX", b"draft"), ("fig.PDF", b"figure")])) ) as archive:
            found, _ = inspect_zip(archive, "example.zip")
        self.assertEqual(len(found), 2)

    def test_nested_template_reported(self):
        nested = zip_bytes([("docs/old.tex", b"draft")])
        with zipfile.ZipFile(io.BytesIO(zip_bytes([("bootstrap.zip", nested)]))) as archive:
            found, count = inspect_zip(archive, "source.zip")
        self.assertEqual(found, ["source.zip!bootstrap.zip!docs/old.tex"])
        self.assertEqual(count, 2)

    def test_nested_budget_failure_is_not_pass(self):
        nested = zip_bytes([("README.md", b"guide")])
        with zipfile.ZipFile(io.BytesIO(zip_bytes([("bootstrap.zip", nested)]))) as archive:
            with self.assertRaises(ValueError):
                inspect_zip(archive, "source.zip", budget=[1])

    def test_depth_failure_is_not_pass(self):
        with zipfile.ZipFile(io.BytesIO(zip_bytes([("script.py", b"pass")]))) as archive:
            with self.assertRaises(ValueError):
                inspect_zip(archive, "source.zip", depth=5)


if __name__ == "__main__":
    unittest.main()
