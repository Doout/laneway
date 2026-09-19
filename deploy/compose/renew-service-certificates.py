#!/usr/bin/env python3
"""Renew Compose controller/relay identities under the existing online issuer."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

DAY = 86400
ROLES = ('controller', 'relay')


def run(*args):
    return subprocess.check_output([str(arg) for arg in args], text=True).strip()


def valid_for(cert, seconds):
    return subprocess.run(['openssl', 'x509', '-in', str(cert), '-noout',
                           '-checkend', str(seconds)], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def identity(cert, role):
    san = run('openssl', 'x509', '-in', cert, '-noout', '-ext', 'subjectAltName')
    entries = sorted(value.strip() for value in san.split('\n', 1)[1].split(','))
    uris = [value[4:] for value in entries if value.startswith('URI:')]
    match = re.fullmatch(r'spiffe://laneway/network/([0-9a-f]{32})/' + role +
                         r'/([0-9a-f]{32})', uris[0]) if len(uris) == 1 else None
    if not match or any(not value.startswith(('URI:', 'DNS:', 'IP Address:')) for value in entries):
        raise ValueError('Unexpected certificate identity for ' + role)
    return match.groups(), entries


def replace(source, target):
    # Replace complete files; Compose recreation picks up the new bind-mount inode.
    stat = target.stat()
    fd, name = tempfile.mkstemp(prefix='.renew-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as output, source.open('rb') as content:
            shutil.copyfileobj(content, output)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), stat.st_mode & 0o777)
            os.fchown(output.fileno(), stat.st_uid, stat.st_gid)
        os.replace(name, target)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def renew(base, force=False, check=False):
    pki = base / 'generated/pki'
    due = any(not valid_for(pki / (role + '.crt'), 7 * DAY) for role in ROLES)
    # Warn/fail ahead of the next leaf renewal; never auto-rotate trust anchors.
    for name in ('ca.crt', 'intermediate-chain.crt'):
        if not valid_for(pki / name, 37 * DAY):
            raise ValueError(name + ' requires operator renewal within 37 days')
    if check or not (due or force):
        print('Renewal required.' if due else 'Service certificates have more than seven days remaining.')
        return
    compose = ['docker', 'compose', '--project-directory', str(base), '--env-file',
               str(base / '.env'), '-f', str(base / 'compose.yaml')]
    config = json.loads(run(*compose, '--profile', 'tools', 'config', '--format', 'json'))
    image = config['services']['admin']['image']
    if '@sha256:' not in image:
        raise ValueError('The administrator image must be pinned by digest')
    backup_root = base / 'generated/backups/certificate-renewal'
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(backup_root, 0o700)
    backup = Path(tempfile.mkdtemp(prefix='renew-', dir=backup_root))
    candidate = backup / 'candidate'
    candidate.mkdir(mode=0o700)
    for role in ROLES:
        for suffix in ('.crt', '.key'):
            shutil.copy2(pki / (role + suffix), backup / (role + suffix))
        (network, service), sans = identity(pki / (role + '.crt'), role)
        command = ['docker', 'run', '--rm', '--network', 'none', '--read-only',
                   '--cap-drop', 'ALL', '--cap-add', 'DAC_READ_SEARCH',
                   '--security-opt', 'no-new-privileges', '--user', '0:0',
                   '-v', str(pki) + ':/issuer:ro', '-v', str(candidate) + ':/out',
                   '--entrypoint', '/usr/local/bin/laneway', image, 'pki', role,
                   '-ca-cert', '/issuer/intermediate-chain.crt', '-ca-key', '/issuer/intermediate.key',
                   '-network-id', network, '-service-id', service, '-validity', '720h',
                   '-out-cert', '/out/' + role + '.crt', '-out-key', '/out/' + role + '.key']
        for prefix, flag in [('DNS:', '-dns'), ('IP Address:', '-ip')]:
            values = [value[len(prefix):] for value in sans if value.startswith(prefix)]
            if values:
                command += [flag, ','.join(values)]
        run(*command)
        cert, key = candidate / (role + '.crt'), candidate / (role + '.key')
        run('openssl', 'verify', '-CAfile', pki / 'ca.crt', '-untrusted',
            pki / 'intermediate-chain.crt', cert)
        if identity(cert, role)[1] != sans or not valid_for(cert, 29 * DAY):
            raise ValueError('Replacement identity or validity mismatch')
        if run('openssl', 'x509', '-in', cert, '-pubkey', '-noout') != run('openssl', 'pkey', '-in', key, '-pubout'):
            raise ValueError('Replacement private key does not match certificate')
    restart = compose + ['up', '-d', '--no-deps', '--force-recreate', '--wait',
                         '--wait-timeout', '120', *ROLES]
    try:
        for role in ROLES:
            for suffix in ('.crt', '.key'):
                replace(candidate / (role + suffix), pki / (role + suffix))
        run(*restart)
    except BaseException:
        for role in ROLES:
            for suffix in ('.crt', '.key'):
                replace(backup / (role + suffix), pki / (role + suffix))
        run(*restart)
        raise
    print('Renewed controller and relay certificates; both services healthy. Backup: ' + str(backup))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path('/opt/laneway'))
    parser.add_argument('--force', action='store_true')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root')
    os.umask(0o077)
    with open('/run/lock/laneway-certificate-renewal.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        renew(args.directory.resolve(), args.force, args.check)
