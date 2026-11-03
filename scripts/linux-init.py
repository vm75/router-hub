#!/usr/bin/env python3
"""Entware-style service adapter for the isolated native Linux configuration."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import tomllib

location = Path(__file__).resolve()
# Installed copies live under data/linux/init.d.
repo = location.parents[3] if location.parent.name == 'init.d' else location.parents[1]
config = Path(os.environ.get('ROUTER_HUB_CONFIG', repo / 'data/linux/router-hub.toml')).resolve()
with config.open('rb') as stream:
    cfg = tomllib.load(stream)
service = 'nginx' if Path(sys.argv[0]).name.endswith('nginx') else 'router-hub'
action = sys.argv[1] if len(sys.argv) > 1 else 'check'
nginx = cfg['nginx']
runtime = Path(cfg['paths']['runtime_dir'])
pidfile = Path(nginx['pid_path']) if service == 'nginx' else runtime / 'router-hub-init.pid'


def process_id():
    try:
        pid = int(pidfile.read_text().strip())
        executable = Path(f'/proc/{pid}/exe').resolve().name
        if pid > 1 and executable == service:
            os.kill(pid, 0)
            return pid
    except (OSError, ValueError):
        pass
    if service == 'router-hub':
        # Also recognize a foreground server launched with this configuration.
        for proc in Path('/proc').glob('[0-9]*'):
            try:
                args = (proc / 'cmdline').read_bytes().split(b'\0')
                if (proc / 'exe').resolve().name != service or b'serve' not in args:
                    continue
                index = args.index(b'--config')
                candidate = Path(os.fsdecode(args[index + 1]))
                if not candidate.is_absolute():
                    candidate = (proc / 'cwd').resolve() / candidate
                if candidate.resolve() == config:
                    return int(proc.name)
            except (OSError, ValueError, IndexError):
                continue
    return None


def run_nginx(*args):
    command = [cfg['commands']['nginx']]
    if nginx.get('prefix_path'):
        command += ['-p', nginx['prefix_path']]
    return subprocess.call(command + ['-c', nginx['config_path'], *args])


def stop():
    pid = process_id()
    if pid is None:
        return
    os.kill(pid, signal.SIGQUIT if service == 'nginx' else signal.SIGTERM)
    for _ in range(100):
        if process_id() != pid:
            return
        time.sleep(0.1)
    raise RuntimeError('Service did not stop within 10 seconds')


try:
    if action in ('check', 'status'):
        alive = process_id() is not None
        print('running' if alive else 'stopped')
        sys.exit(0 if alive else 1)
    if action in ('stop', 'restart'):
        stop()
    if action in ('start', 'restart'):
        if process_id() is None:
            if service == 'nginx':
                result = run_nginx('-t')
                sys.exit(result if result else run_nginx())
            if cfg['server'].get('daemonize', False):
                raise RuntimeError('Set server.daemonize = false for the Linux init adapter')
            binary = repo / 'target/release/router-hub'
            if not binary.exists():
                binary = repo / 'target/debug/router-hub'
            runtime.mkdir(parents=True, exist_ok=True)
            with Path(cfg['paths']['log_file']).open('ab') as log:
                child = subprocess.Popen([str(binary), '--config', str(config), '--linux-mode', 'serve'],
                                         cwd=repo, stdin=subprocess.DEVNULL, stdout=log,
                                         stderr=log, start_new_session=True)
            pidfile.write_text(str(child.pid))
            time.sleep(0.2)
            if child.poll() is not None:
                raise RuntimeError('Router Hub exited; inspect its log')
    elif action in ('reconfigure', 'reload'):
        if service == 'nginx':
            sys.exit(run_nginx('-t') or run_nginx('-s', 'reload'))
        pid = process_id()
        if pid is None:
            raise RuntimeError('Router Hub is stopped')
        os.kill(pid, signal.SIGUSR1)
    elif action != 'stop':
        raise RuntimeError('Usage: start|stop|restart|check|status|reconfigure|reload')
except (OSError, RuntimeError) as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)
