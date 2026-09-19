import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('renewal', Path(__file__).with_name('renew-service-certificates.py'))
renewal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renewal)


class RenewalTests(unittest.TestCase):
    def test_noop_does_not_restart_services(self):
        with patch.object(renewal, 'valid_for', return_value=True), patch.object(renewal, 'run') as run:
            renewal.renew(Path('/unused'))
        run.assert_not_called()

    def test_expiring_authority_stops_renewal(self):
        with patch.object(renewal, 'valid_for', return_value=False), patch.object(renewal, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'operator renewal'):
                renewal.renew(Path('/unused'))
        run.assert_not_called()

    def test_identity_rejects_wrong_role(self):
        value = 'X509v3 Subject Alternative Name:\n DNS:example.com, URI:spiffe://laneway/network/' + 'a' * 32 + '/relay/' + 'b' * 32
        with patch.object(renewal, 'run', return_value=value):
            self.assertEqual(renewal.identity(Path('cert'), 'relay')[0], ('a' * 32, 'b' * 32))
            with self.assertRaises(ValueError):
                renewal.identity(Path('cert'), 'controller')

    def exercise_rotation(self, fail):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            pki = base / 'generated/pki'
            pki.mkdir(parents=True)
            for role in renewal.ROLES:
                for suffix in ('.crt', '.key'):
                    path = pki / (role + suffix)
                    path.write_text('old')
                    path.chmod(0o400)
            restarts = []

            def command(*args):
                if 'config' in args:
                    return json.dumps({'services': {'admin': {'image': 'admin@sha256:example'}}})
                if args[:2] == ('docker', 'run'):
                    output = next(str(arg)[:-5] for arg in args if str(arg).endswith(':/out'))
                    role = args[args.index('pki') + 1]
                    for suffix in ('.crt', '.key'):
                        (Path(output) / (role + suffix)).write_text('new')
                if 'up' in args:
                    restarts.append(True)
                    if fail and len(restarts) == 1:
                        raise RuntimeError('unhealthy')
                return 'public-key'

            with patch.object(renewal, 'run', side_effect=command), patch.object(renewal, 'valid_for', return_value=True), patch.object(renewal, 'identity', return_value=(('a' * 32, 'b' * 32), ['DNS:example.com'])):
                if fail:
                    with self.assertRaisesRegex(RuntimeError, 'unhealthy'):
                        renewal.renew(base, force=True)
                else:
                    renewal.renew(base, force=True)
            self.assertEqual(len(restarts), 2 if fail else 1)
            for path in pki.iterdir():
                self.assertEqual(path.read_text(), 'old' if fail else 'new')
                self.assertEqual(path.stat().st_mode & 0o777, 0o400)

    def test_rotation(self):
        self.exercise_rotation(False)

    def test_failed_health_restores_certificates(self):
        self.exercise_rotation(True)


if __name__ == '__main__':
    unittest.main()
