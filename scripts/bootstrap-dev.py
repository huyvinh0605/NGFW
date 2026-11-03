#!/usr/bin/env python3
"""Download project dependencies without starting the appliance or lab traffic."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys
import venv

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], cwd: Path = ROOT) -> None:
    print('+ ' + ' '.join(str(part) for part in command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def require_tool(name: str, version_args: list[str], minimum: tuple[int, ...]) -> str:
    executable = shutil.which(name)
    if not executable:
        raise RuntimeError(f'{name} is missing. Install the toolchain described in docs/SETUP.md and retry.')
    result = subprocess.run([executable, *version_args], cwd=ROOT,
                            check=True, capture_output=True, text=True)
    match = re.search(r'(\d+)\.(\d+)', result.stdout)
    if not match or tuple(map(int, match.groups())) < minimum:
        wanted = '.'.join(map(str, minimum))
        raise RuntimeError(f'{name} >= {wanted} is required; found {result.stdout.strip()}')
    print(result.stdout.strip(), flush=True)
    return executable


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--with-lab-tools', action='store_true',
                        help='install Requests/Paramiko into .venv for the lab controller')
    parser.add_argument('--with-ml', action='store_true',
                        help='install the optional experimental ML requirements into .venv')
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.error('Python 3.10 or newer is required')

    # Check all required toolchains before changing dependency directories.
    go = require_tool('go', ['version'], (1, 22))
    require_tool('node', ['--version'], (22, 0))
    npm = shutil.which('npm.cmd' if sys.platform == 'win32' else 'npm')
    if not npm:
        raise RuntimeError('npm is missing. Install Node.js with npm and retry.')
    for path in (ROOT / 'go.sum', ROOT / 'web/package-lock.json'):
        if not path.is_file():
            raise RuntimeError(f'Incomplete checkout: {path.relative_to(ROOT)} is missing')

    # Archived/generated Go clients are evidence, not application packages.
    # Git ignores the entire directory; Go needs its own local module boundary.
    marker = ROOT / 'artifacts/go.mod'
    if not marker.exists():
        marker.parent.mkdir(exist_ok=True)
        marker.write_text('module ngfw.local/artifacts\n\ngo 1.22\n', encoding='utf-8')

    run([go, 'mod', 'download'])
    run([npm, 'ci', '--no-fund', '--no-audit'], ROOT / 'web')

    if args.with_lab_tools or args.with_ml:
        environment = ROOT / '.venv'
        python = environment / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
        if not python.is_file():
            if environment.exists():
                raise RuntimeError('.venv already exists without a usable Python executable; inspect it before retrying.')
            venv.EnvBuilder(with_pip=True).create(environment)
        requirements = []
        if args.with_lab_tools:
            requirements.append(ROOT / 'tests/integration/requirements.txt')
        if args.with_ml:
            requirements.append(ROOT / 'ml/service/requirements.txt')
        for requirement in requirements:
            run([str(python), '-m', 'pip', 'install', '-r', str(requirement)])
        run([str(python), '-m', 'pip', 'check'])
        print(f'Python environment: {python}', flush=True)

    print('Dependencies ready. See docs/SETUP.md for build/run commands. No services or lab traffic were started.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'Setup failed: {error}', file=sys.stderr)
        raise SystemExit(1)
