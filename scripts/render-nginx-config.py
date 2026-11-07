#!/usr/bin/env python3
"""Prepare a new Linux lab using the current Jinja bundle (never migrate old configs)."""
import argparse
import json
import os
import shutil
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('bundle', type=Path)
parser.add_argument('output', type=Path)
parser.add_argument('--inputs-dir', required=True, type=Path)
parser.add_argument('--var-dir', required=True)
parser.add_argument('--pid-path', required=True)
parser.add_argument('--error-log-path', required=True)
parser.add_argument('--acme-directory', required=True)
parser.add_argument('--http-port', type=int, required=True)
parser.add_argument('--https-port', type=int, required=True)
parser.add_argument('--temp-dir', type=Path)
args = parser.parse_args()
env = Environment(loader=FileSystemLoader(args.bundle), undefined=StrictUndefined,
                  autoescape=False, trim_blocks=True, lstrip_blocks=True)
settings = dict(router_ip='127.0.0.1', http_port=args.http_port,
                https_port=args.https_port, var_dir=args.var_dir,
                acme_challenge_dir=args.acme_directory, nginx_daemon=True, nginx_user='',
                temp_dir=str((args.temp_dir or args.output.resolve().parent / 'tmp').resolve()))
Path(settings['temp_dir']).mkdir(parents=True, exist_ok=True)
context = dict(settings, nginx_is_root=os.geteuid() == 0, pid_path=args.pid_path, error_log_path=args.error_log_path)
root = args.output
for directory in ('module.d', 'domains-available', 'domains-enabled', 'certs/default'):
    (root / directory).mkdir(parents=True, exist_ok=True)
for directory in ('log/nginx', 'run'):
    (Path(args.var_dir) / directory).mkdir(parents=True, exist_ok=True)
for path in args.bundle.rglob('*'):
    relative = path.relative_to(args.bundle)
    if not path.is_file() or relative.parts[0] in ('nginx.deploy', 'tests', 'examples', 'templates'):
        continue
    runtime = relative.parts[0] in ('conf.d', 'ban-shield', 'settings') or str(relative) in (
        'nginx.conf.jinja', 'resolver.conf.jinja', 'mime.types', 'dhparams.pem',
        'snippets/ssl.conf.jinja', 'snippets/acme-challenge.conf.jinja',
        'snippets/restrict.conf.jinja', 'snippets/security-headers.conf')
    if not runtime or path.suffix == '.md' or relative.parts[0] == 'settings' and path.suffix == '.jinja':
        continue
    if relative.parts[0] == 'settings':
        target = args.inputs_dir / relative.name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() and not target.is_symlink():
            shutil.copyfile(path, target)
        # Only final nginx includes belong in the runtime tree.
        if path.suffix != '.conf':
            continue
    target = root / str(relative).removesuffix('.jinja')
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        continue
    if path.suffix == '.jinja':
        content = env.get_template(str(relative)).render(**context)
        target.write_text(content)
    else:
        shutil.copyfile(path, target)
state = args.inputs_dir / 'nginx.toml'
if not state.exists() and not state.is_symlink():
    values = '\n'.join(f'{key} = {json.dumps(value)}' for key, value in settings.items())
    state.write_text(f'allowed_ips = []\nfree_subdomains = []\n\n[global]\n{values}\n\n[site_defaults]\n')
