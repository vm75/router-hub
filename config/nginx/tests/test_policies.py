"""Integration coverage for route policies and reviewed healthcheck log suppression."""
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import tomllib
import unittest

from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_SNIPPETS = {
    'ssl.conf.jinja', 'acme-challenge.conf.jinja', 'restrict.conf.jinja', 'security-headers.conf',
}
HA_UA = 'Home-Assistant/test'
HA_HOST = 'video.example.test'
LOGS = {}


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Backend(BaseHTTPRequestHandler):
    records = []

    def do_GET(self):
        self.records.append((self.path, dict(self.headers)))
        if self.path == '/quiet/error' or 'broken=1' in self.path:
            self.close_connection = True
            return
        if self.headers.get('Upgrade') == 'websocket':
            self.send_response(101)
            self.send_header('Upgrade', 'websocket')
            self.send_header('Connection', 'upgrade')
            self.end_headers()
            return
        status = 500 if 'fail=1' in self.path else (404 if 'missing' in self.path else 200)
        body = (b'data: ping\n\n' if self.path == '/api/updates' else self.path.encode())
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'text/event-stream' if self.path == '/api/updates' else 'text/plain')
        self.send_header('ETag', '"backend-tag"')
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *args):
        pass


@contextmanager
def fixture(empty_filter=False):
    with tempfile.TemporaryDirectory(prefix='router-hub-policies-') as tmp, ThreadingHTTPServer(('127.0.0.1', 0), Backend) as backend:
        dest = Path(tmp)
        upstream = f'http://127.0.0.1:{backend.server_port}'
        sites = tomllib.loads((ROOT / 'examples/sites.toml').read_text())['sites']
        hostnames = [HA_HOST, 'policy.example.test', 'custom.example.test']
        for site in sites.values():
            hostnames.extend(site.get('server_name', '').split())
        host_map = ''.join(f'{host} {upstream};\n' for host in hostnames)
        mounted = ['app', 'app-dev', 'spa', 'spa-dev', 'music', 'music-dev']
        mounted_map = ''.join(f'{name} {upstream};\n' for name in mounted)
        # Only synthetic examples enter this fixture; deployment overrides are never read.
        suppress = '' if empty_filter else (ROOT / 'examples/access_log_suppress.conf').read_text()
        env = Environment(
            loader=ChoiceLoader([DictLoader({
                'settings/allowed_ips.txt': '127.0.0.2/32\n',
                'settings/domains.conf': host_map,
                'settings/subdomains.conf': host_map,
                'settings/subfolders.conf': mounted_map,
                'settings/access_log_suppress.conf': suppress,
                'settings/security_trap_allow.conf': (ROOT / 'examples/security_trap_allow.conf').read_text(),
            }), FileSystemLoader(ROOT)]),
            undefined=StrictUndefined, autoescape=False, trim_blocks=True, lstrip_blocks=True,
        )
        context = dict(var_dir=str(dest / 'var'), router_ip='127.0.0.1', http_port=free_port(),
                       https_port=free_port(), acme_challenge_dir=str(dest / 'acme'))
        for folder in ('var/log/nginx', 'var/run', 'certs/default', 'acme', 'module.d', 'conf.d', 'snippets', 'settings', 'ban-shield'):
            (dest / folder).mkdir(parents=True, exist_ok=True)
        for name in ('nginx.conf.jinja', 'resolver.conf.jinja', 'mime.types', 'dhparams.pem'):
            (dest / name.removesuffix('.jinja')).write_text(env.get_template(name).render(**context))
        main = dest / 'nginx.conf'
        main.write_text(main.read_text().replace('http {', 'http {\n' + '\n'.join(
            f'    {module}_temp_path {dest}/{module}-temp;'
            for module in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi')
        )))
        for folder in ('conf.d', 'settings', 'snippets', 'ban-shield'):
            for source in (ROOT / folder).iterdir():
                if not source.name.endswith(('.conf', '.conf.jinja')):
                    continue
                if folder == 'snippets' and source.name not in RUNTIME_SNIPPETS:
                    continue
                (dest / folder / source.name.removesuffix('.jinja')).write_text(
                    env.get_template(f'{folder}/{source.name}').render(**context)
                )
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(dest / 'certs/default/privkey.pem'),
                        '-out', str(dest / 'certs/default/fullchain.pem'),
                        '-days', '1', '-subj', '/CN=fixture'], check=True, capture_output=True)
        enabled = dest / 'domains-enabled'
        enabled.mkdir()
        for index, site in enumerate(sites.values()):
            options = dict(context, **site)
            kind = options.pop('kind')
            if kind == 'subfolder':
                continue
            directory = enabled / f'profile-{index}'
            directory.mkdir()
            (directory / 'root.conf').write_text(env.get_template(f'templates/{kind}.conf.jinja').render(**options))
        for host in (HA_HOST, 'policy.example.test'):
            directory = enabled / host
            directory.mkdir()
            options = dict(context, server_name=host, domain=host, enable_subfolders=False,
                           enable_lanonly=False, routes=[
                               dict(path='/quiet', access_log=False, children=[
                                   dict(path='/quiet/inherited'),
                                   dict(path='/quiet/logged', access_log=True),
                               ]),
                               dict(path='/quiet-spa', access_log=False, spa_fallback='/index.html', hide_etag=True),
                               dict(path='/api/updates', proxy_transport='sse', access_log=False),
                           ])
            (directory / 'root.conf').write_text(env.get_template('templates/subdomain.conf.jinja').render(**options))
        directory = enabled / 'mounted'
        (directory / 'subfolders-enabled').mkdir(parents=True)
        (directory / 'root.conf').write_text(env.get_template('templates/domain.conf.jinja').render(
            **context, server_name='mounted.example.test', domain='mounted', enable_lanonly=False,
        ))
        for name, site in sites.items():
            if site['kind'] == 'subfolder':
                options = dict(context, **site)
                (directory / 'subfolders-enabled' / (site['subfolder'] + '.conf')).write_text(
                    env.get_template('templates/subfolder.conf.jinja').render(**options)
                )
        for mount in ('app', 'app-dev'):
            (directory / 'subfolders-enabled' / (mount + '.conf')).write_text(
                env.get_template('templates/subfolder.conf.jinja').render(
                    **context, subfolder=mount, enable_lanonly=False,
                    routes=[dict(path='/quiet', access_log=False, spa_fallback='/index.html')],
                )
            )
        # Representative unchanged raw custom source keeps its old runtime includes.
        custom = enabled / 'custom'
        custom.mkdir()
        raw = (ROOT / 'tests/fixtures/custom-server.conf').read_text()
        (custom / 'root.conf').write_text(raw)
        subprocess.run(['nginx', '-t', '-p', str(dest) + '/', '-c', 'nginx.conf', '-e', str(dest / 'syntax.log')],
                       check=True, capture_output=True)
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        process = subprocess.Popen(['nginx', '-p', str(dest) + '/', '-c', 'nginx.conf', '-e', str(dest / 'startup.log')],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1', context['https_port']), timeout=0.1):
                        break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError(process.stderr.read())
                    time.sleep(0.02)
            else:
                raise RuntimeError('nginx listener did not start')
            yield dest, context['https_port']
            assert (custom / 'root.conf').read_text() == raw
        finally:
            process.send_signal(signal.SIGQUIT)
            process.communicate(timeout=5)
            LOGS.clear()
            LOGS.update({name: (dest / 'var/log/nginx' / name).read_text()
                         for name in ('access.log', 'traps.log', 'error.log')})
            backend.shutdown()
            thread.join(timeout=5)


def request(port, path, host='policy.example.test', method='GET', ua='TestClient', source='127.0.0.1', headers=None):
    connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=3,
        source_address=(source, 0), context=ssl._create_unverified_context())
    try:
        connection.request(method, path, headers=dict({'Host': host, 'User-Agent': ua}, **(headers or {})))
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


@unittest.skipUnless(shutil.which('nginx') and shutil.which('openssl'), 'nginx and openssl required')
class Policies(unittest.TestCase):
    def test_healthcheck_filter_logging_and_failures(self):
        with fixture() as (dest, port):
            self.assertEqual(request(port, '/Sessions', HA_HOST, ua=HA_UA)[0], 200)
            self.assertEqual(request(port, '/Sessions?test=1', HA_HOST, ua=HA_UA)[0], 200)
            self.assertEqual(request(port, '/Sessions?fail=1', HA_HOST, ua=HA_UA)[0], 500)
            self.assertEqual(request(port, '/Sessions?missing=1', HA_HOST, ua=HA_UA)[0], 404)
            self.assertEqual(request(port, '/Sessions?broken=1', HA_HOST, ua=HA_UA)[0], 502)
            for path, host, method, ua, source in (
                ('/SessionsExtra', HA_HOST, 'GET', HA_UA, '127.0.0.1'),
                ('/Sessions', 'policy.example.test', 'GET', HA_UA, '127.0.0.1'),
                ('/Sessions', HA_HOST, 'POST', HA_UA, '127.0.0.1'),
                ('/Sessions', HA_HOST, 'GET', 'OtherClient', '127.0.0.1'),
                ('/Sessions', HA_HOST, 'GET', HA_UA, '127.0.0.2'),
            ):
                self.assertEqual(request(port, path, host, method, ua, source)[0], 200)
            for path in ('/quiet/poll', '/quiet/inherited/poll', '/quiet/missing'):
                request(port, path)
            request(port, '/quiet/logged/poll')
            request(port, '/ordinary')
            self.assertEqual(request(port, '/quiet/error')[0], 502)
            request(port, '/quiet-spa/missing')
            request(port, '/app/quiet/missing', 'mounted.example.test')
            request(port, '/app-dev/quiet/missing', 'mounted.example.test')
            self.assertEqual(request(port, '/api/updates')[0], 200)
            self.assertEqual(request(port, '/quiet/socket', headers={'Upgrade': 'websocket', 'Connection': 'upgrade'})[0], 101)
            for path in ('/quiet/.env', '/Sessions?probe=/etc/passwd', '/xmlrpc.php'):
                with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
                    request(port, path, HA_HOST, ua=HA_UA)
            allowed = '/wp-content/uploads/nanogallery2/nano_photos_provider2.php'
            self.assertEqual(request(port, allowed, 'gallery.example.test')[0], 200)
            with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
                request(port, allowed, 'gallery.example.test', ua='curl/8.0')
        # Assert after nginx exits, including buffered terminal WS/SSE log records.
        normal, traps, errors = (LOGS[name] for name in ('access.log', 'traps.log', 'error.log'))
        for path in ('/quiet/poll', '/quiet/inherited/poll', '/quiet/missing', '/quiet/error',
                     '/quiet-spa/missing', '/api/updates', '/quiet/socket'):
            self.assertNotIn(' ' + path + ' HTTP/', normal)
        self.assertIn('/quiet/logged/poll', normal)
        self.assertIn('/ordinary', normal)
        self.assertNotIn('GET /index.html HTTP/', normal)  # quiet SPA fallback remains quiet
        self.assertIn('/quiet/error', errors)
        self.assertIn('/quiet/.env', traps)
        self.assertIn('/quiet/.env', normal)
        self.assertIn('trap="1"', traps)
        xmlrpc = next(line for line in traps.splitlines() if 'GET /xmlrpc.php HTTP/1.1' in line)
        trap_match = re.match(r'^(?P<ip>[0-9A-Fa-f:.]+).*trap="1"', xmlrpc)
        self.assertIsNotNone(trap_match)
        self.assertEqual(trap_match['ip'], '127.0.0.1')
        bot_line = next(line for line in traps.splitlines() if 'badbot="1"' in line)
        self.assertIsNotNone(re.match(r'^(?P<ip>[0-9A-Fa-f:.]+).*badbot="1"', bot_line))
        self.assertIn('GET /Sessions HTTP/1.1" 444', normal)
        self.assertIn('GET /Sessions HTTP/1.1" 500', normal)
        self.assertIn('GET /Sessions HTTP/1.1" 404', normal)
        self.assertIn('GET /Sessions HTTP/1.1" 502', normal)
        self.assertIn('/SessionsExtra', normal)
        self.assertIn('POST /Sessions', normal)
        self.assertIn('OtherClient', normal)
        self.assertIn('127.0.0.2 - -', normal)
        health_success = [line for line in normal.splitlines() if line.startswith('127.0.0.1 ')
                          and 'GET /Sessions HTTP/1.1" 200' in line
                          and f'"{HA_UA}" host="{HA_HOST}"' in line]
        self.assertEqual(health_success, [])

    def test_empty_filter_and_custom_runtime(self):
        with fixture(empty_filter=True) as (dest, port):
            self.assertEqual(request(port, '/Sessions', HA_HOST, ua=HA_UA)[0], 200)
            for path in ('/', '/special'):
                self.assertEqual(request(port, path, 'custom.example.test')[0], 200)
        self.assertIn('GET /Sessions HTTP/1.1" 200', LOGS['access.log'])

    def test_ported_profiles(self):
        with fixture() as (dest, port):
            status, headers, _ = request(port, '/', 'books.example.test', source='127.0.0.2', headers={'Authorization': 'Basic fixture'})
            self.assertEqual(status, 200)
            self.assertEqual(Backend.records[-1][1].get('Authorization'), 'Basic fixture')
            self.assertEqual(request(port, '/admin', 'vault.example.test')[0], 403)
            self.assertEqual(request(port, '/admin', 'vault.example.test', source='127.0.0.2')[0], 200)
            for host, path, burst in (('vault.example.test', '/identity/connect/token', 5), ('gallery.example.test', '/wp-login.php', 3)):
                statuses = [request(port, path, host)[0] for _ in range(burst + 2)]
                self.assertIn(429, statuses)
            for mount in ('spa', 'spa-dev'):
                prefix = '/' + mount
                status, headers, body = request(port, prefix + '/missing', 'mounted.example.test')
                self.assertEqual((status, body), (200, b'/index.html'))
                self.assertIn('no-store', headers['Cache-Control'])
                self.assertEqual(request(port, prefix + '/api/admin/', 'mounted.example.test')[0], 403)
                status, headers, body = request(port, prefix + '/api/updates', 'mounted.example.test')
                self.assertEqual(body, b'data: ping\n\n')
                self.assertNotIn('Connection', Backend.records[-1][1])
                self.assertEqual(headers['Access-Control-Allow-Origin'], '*')
                for path in ('/service-worker.js', '/manifest.json', '/page.html'):
                    response = request(port, prefix + path, 'mounted.example.test')
                    self.assertIn('no-store', response[1]['Cache-Control'])
                self.assertIn('immutable', request(port, prefix + '/assets/main.js', 'mounted.example.test')[1]['Cache-Control'])
                self.assertNotIn('ETag', request(port, prefix + '/', 'mounted.example.test')[1])
                self.assertEqual(request(port, prefix + '/socket', 'mounted.example.test', headers={'Upgrade': 'websocket', 'Connection': 'upgrade'})[0], 101)
            for mount, source in (('music', '127.0.0.1'), ('music-dev', '127.0.0.2')):
                for path in ('/sw.js', '/page.html', '/config', '/auth'):
                    response = request(port, '/' + mount + path, 'mounted.example.test', source=source)
                    self.assertEqual(response[0], 200)
                    self.assertIn('no-store', response[1]['Cache-Control'])
            self.assertEqual(request(port, '/music-dev/', 'mounted.example.test')[0], 403)


if __name__ == '__main__':
    unittest.main()
