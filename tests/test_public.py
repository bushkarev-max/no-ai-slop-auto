"""Synthetic fixtures only; no real credentials or personal data."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('guard', ROOT / 'scripts/check_public.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

class PublicGuardTests(unittest.TestCase):
    def test_current_package(self):
        self.assertEqual(guard.scan(ROOT), [])

    def test_sensitive_patterns(self):
        samples = {
            'private-key': '-----BEGIN ' + 'PRIVATE KEY-----',
            'token': 'gh' + 'p_' + 'A' * 36,
            'credential': 'pass' + 'word="' + 'z' * 16 + '"',
            'email': 'sample' + '@' + 'example' + '.invalid',
            'local-path': '/' + 'Users/' + 'example/Documents',
            'ip-address': '.'.join(['192', '0', '2', '1']),
            'url-credentials': 'https://' + 'user:pass' + '@example.invalid',
            'unapproved-github-url': 'https://' + 'github.com/' + 'example/private-repo',
        }
        for category, sample in samples.items():
            with self.subTest(category=category):
                self.assertIn(category, [x[1] for x in guard.findings(sample)])

    def test_safe_public_url(self):
        self.assertEqual(guard.findings('https://github.com/bushkarev-max/no-ai-slop-auto'), [])

    def test_confusable_repository_is_blocked(self):
        value = 'https://' + 'github.com/' + 'bushkarev-max/no-ai-slop-auto-private'
        self.assertTrue(guard.findings(value))

    def test_unapproved_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'unexpected.txt').write_text('safe')
            (root / 'alias').symlink_to(root / 'unexpected.txt')
            categories = [x[2] for x in guard.scan(root)]
            self.assertIn('unapproved-file', categories)
            self.assertIn('symlink', categories)
            self.assertIn('missing-file', categories)

    def test_binary_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'LICENSE').write_bytes(b'\0')
            self.assertIn('non-text', [x[2] for x in guard.scan(root)])

if __name__ == '__main__':
    unittest.main()
