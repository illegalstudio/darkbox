import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SyncReferences(unittest.TestCase):
    def test_schema_reproduces_without_writes(self):
        subprocess.run([sys.executable, str(ROOT / "scripts/sync_schema.py"), "--check"], cwd=ROOT, check=True, capture_output=True)

    def test_independent_vectors_reproduce_without_writes(self):
        subprocess.run([sys.executable, str(ROOT / "scripts/sync_vectors.py"), "--check"], cwd=ROOT, check=True, capture_output=True)
