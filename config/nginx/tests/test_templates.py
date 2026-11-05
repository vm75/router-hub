"""Run with Python + Jinja2, nginx and openssl; all outputs stay in /tmp."""
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import itertools
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader, StrictUndefined, UndefinedError

ROOT = Path(__file__).resolve().parents[1]
FLAGS = (
    'enable_large_upload', 'enable_longlived', 'enable_streaming',
    'enable_byte_ranges', 'cache_policy', 'enable_lanonly',
)


# Each previous file has an explicit replacement using the three templates.
PROFILES = {
    'domain/basic': dict(enable_lanonly=False),
    'domain/lan-only': dict(enable_lanonly=True),
    'domain/reverse-proxy': dict(enable_lanonly=False, disable_root=False,
                                 enable_subfolders=False, enable_longlived=True),
    'subdomain/lan-only-large-upload': dict(enable_lanonly=True, enable_large_upload=True, clear_origin=True),
    'subdomain/lan-only-long-lived': dict(enable_lanonly=True, enable_longlived=True),
    'subdomain/lan-only-media-streaming': dict(enable_lanonly=True, enable_longlived=True, enable_streaming=True),
    'subdomain/lan-only': dict(enable_lanonly=True, cache_policy='pwa'),
    'subdomain/media-streaming-sessions': dict(enable_lanonly=False, enable_longlived=True,
                                             enable_streaming=True, enable_restricted_sessions=True),
    'subdomain/media-streaming-upload': dict(enable_lanonly=False, enable_streaming=True, enable_large_upload=True),
    'subdomain/media-streaming': dict(enable_lanonly=False, enable_longlived=True, enable_streaming=True),
    'subdomain/proxy': dict(enable_lanonly=False),
    'subdomain/websocket': dict(enable_lanonly=False, enable_longlived=True),
    'subfolder/lan-only': dict(enable_lanonly=True, enable_streaming=True,
                             enable_longlived=True, proxy_session_timeout='86400s'),
    'subfolder/standard': dict(enable_lanonly=False, enable_streaming=True,
                             enable_longlived=True, proxy_session_timeout='86400s'),
    'subfolder/pwa-app': dict(enable_lanonly=False, enable_streaming=True,
                            enable_byte_ranges=True, cache_policy='no_cache'),
}


class Templates(unittest.TestCase):
    def setUp(self):
        self.env = Environment(
            loader=FileSystemLoader(ROOT), undefined=StrictUndefined,
            autoescape=False, trim_blocks=True, lstrip_blocks=True,
            keep_trailing_newline=True,
        )

    def render(self, kind, **options):
        return self.env.get_template(f'templates/{kind}.conf.jinja').render(
            server_name='example.test', domain='example.test', subfolder='app',
            **options,
        )

    def test_source_extensions_and_includes(self):
        source_dirs = [ROOT / name for name in ('conf.d', 'settings', 'snippets', 'templates', 'ban-shield', 'tests/fixtures')]
        for source in itertools.chain(ROOT.glob('*.conf'), *(d.rglob('*.conf') for d in source_dirs)):
            with self.subTest(source=source.relative_to(ROOT)):
                text = source.read_text()
                self.assertNotIn('{%', text)
                self.assertNotIn('{{', text)
        for source in itertools.chain(ROOT.glob('*.conf.jinja'), *(d.rglob('*.conf.jinja') for d in source_dirs)):
            with self.subTest(source=source.relative_to(ROOT)):
                # All static Jinja include/import paths must resolve after renaming.
                text = source.read_text()
                for name in re.findall(r"{%-?\s*(?:include|import)\s+['\"]([^'\"]+)['\"]", text):
                    self.assertTrue((ROOT / name).is_file(), name)
        for name in ('allowed_ips', 'free_subdomains'):
            self.assertTrue((ROOT / f'settings/{name}.txt').is_file())
            self.assertFalse((ROOT / f'settings/{name}.conf').exists())

    def test_ban_shield_include_boundaries(self):
        general = (ROOT / 'conf.d/01-global.conf.jinja').read_text()
        for declaration in ('log_format ', 'limit_req_zone ', 'limit_conn_zone ', 'map $'):
            self.assertNotIn(declaration, general)
        self.assertIn('include ban-shield/http.conf;', (ROOT / 'conf.d/00-ban-shield.conf').read_text())
        self.assertIn('include ban-shield/server-guard.conf;', (ROOT / 'snippets/ssl.conf.jinja').read_text())
        for name in ('zones', 'maps', 'log-formats', 'log-conditions', 'access-logging'):
            self.assertIn(f'include ban-shield/{name}.conf;', (ROOT / 'ban-shield/http.conf').read_text())

    def test_settings_contain_no_deployment_data(self):
        import tomllib
        self.assertEqual(tomllib.loads((ROOT / 'settings/sites.toml').read_text()), {'sites': {}})
        for name in ('allowed_ips.txt', 'free_subdomains.txt', 'domains.conf', 'subdomains.conf',
                     'subfolders.conf', 'access_log_suppress.conf', 'security_trap_allow.conf'):
            entries = [line for line in (ROOT / 'settings' / name).read_text().splitlines()
                       if line.strip() and not line.lstrip().startswith('#')]
            self.assertEqual(entries, [], name)

    def test_defaults_and_required_inputs(self):
        for kind in ('domain', 'subdomain', 'subfolder'):
            with self.subTest(kind=kind):
                text = self.render(kind)
                self.assertIn('include snippets/restrict.conf;', text)
                if kind == 'domain':
                    self.assertIn('return 404;', text)
                    self.assertIn('subfolders-enabled/*.conf;', text)
                    self.assertNotIn('proxy_pass', text)
                else:
                    self.assertIn('proxy_set_header Upgrade $http_upgrade;', text)
                    self.assertIn('client_max_body_size 100M;', text)
                    self.assertNotIn('proxy_read_timeout', text)
        for kind in ('domain', 'subdomain', 'subfolder'):
            with self.assertRaises(UndefinedError):
                self.env.get_template(f'templates/{kind}.conf.jinja').render()
        text = self.render('domain', enable_subfolders=False, enable_lanonly=False)
        self.assertNotIn('subfolders-enabled', text)
        self.assertNotIn('snippets/restrict.conf', text)

    def test_combinations_have_disjoint_directives(self):
        for bits in itertools.product((False, True), repeat=len(FLAGS)):
            options = dict(zip(FLAGS, bits))
            options['cache_policy'] = 'no_cache' if options['cache_policy'] else 'inherit'
            for kind in ('domain', 'subdomain', 'subfolder'):
                with self.subTest(kind=kind, **options):
                    text = self.render(kind, disable_root=False, **options)
                    names = re.findall(r'^\s*((?:proxy_\w+|client_\w+|send_timeout))\s', text, re.M)
                    singletons = [name for name in names if name != 'proxy_set_header']
                    self.assertEqual(len(singletons), len(set(singletons)))
                    headers = re.findall(r'proxy_set_header\s+(\S+)', text)
                    self.assertEqual(len(headers), len(set(headers)))
                    self.assertIn('proxy_http_version 1.1;', text)
                    self.assertIn('proxy_set_header Upgrade $http_upgrade;', text)
                    self.assertIn('proxy_set_header Connection $connection_upgrade;', text)
                    self.assertEqual('proxy_read_timeout 3600s;' in text, bits[0] or bits[1])
                    self.assertEqual('client_max_body_size 5G;' in text, bits[0])
                    self.assertEqual('proxy_request_buffering off;' in text, bits[0])
                    self.assertEqual('proxy_buffering off;' in text, bits[2])
                    self.assertEqual('proxy_force_ranges on;' in text, bits[3])
                    self.assertEqual('proxy_cache off;' in text, bits[4])
                    self.assertEqual('include snippets/restrict.conf;' in text, bits[5])
                    if bits[4]:
                        self.assertIn('add_header X-Content-Type-Options', text)

    def test_custom_parameters_and_zero_body_limit(self):
        text = self.render(
            'subdomain', enable_large_upload=True, enable_longlived=True,
            large_upload_max_body_size=0, proxy_session_timeout='7200s',
            client_upload_timeout='1200s', proxy_connect_timeout='7s',
        )
        for line in ('client_max_body_size 0;', 'proxy_read_timeout 7200s;',
                     'proxy_send_timeout 7200s;', 'send_timeout 7200s;',
                     'client_body_timeout 1200s;', 'proxy_connect_timeout 7s;'):
            self.assertIn(line, text)
        self.assertIn('client_max_body_size 0;', self.render('subfolder', client_max_body_size=0))
        # Imports must use the current render's context, without caching prior flags.
        self.assertNotIn('proxy_read_timeout', self.render('subdomain'))

    def test_every_previous_variant_has_a_replacement(self):
        for name, options in PROFILES.items():
            with self.subTest(variant=name):
                text = self.render(name.split('/')[0], **options)
                self.assertNotIn('{%', text)
                if 'sessions' in name:
                    self.assertIn('location ^~ /Sessions {', text)
                    self.assertIn('if=$log_traps_only;', text)
                if name.endswith('large-upload'):
                    self.assertIn('proxy_set_header Origin "";', text)
                if name == 'subdomain/lan-only':
                    self.assertIn('add_header Cache-Control $pwa_cache_control', text)
                if name.endswith('pwa-app'):
                    self.assertIn('no-cache, no-store, must-revalidate', text)

    def test_extra_features_on_all_layouts(self):
        for kind in ('domain', 'subdomain', 'subfolder'):
            with self.subTest(kind=kind):
                text = self.render(kind, disable_root=False, cache_policy='pwa',
                                   enable_restricted_sessions=True, clear_origin=True)
                mount = '/app' if kind == 'subfolder' else ''
                self.assertIn(f'location ^~ {mount}/Sessions {{', text)
                self.assertEqual(text.count('proxy_set_header Origin "";'), 2)
                self.assertEqual(text.count('proxy_set_header Upgrade $http_upgrade;'), 2)
                self.assertEqual(text.count('add_header Cache-Control $pwa_cache_control always;'), 2)
                text = self.render(kind, disable_root=False, cache_policy='no_cache')
                self.assertNotIn('add_header Cache-Control $pwa_cache_control', text)
                self.assertIn('add_header Cache-Control "no-cache, no-store, must-revalidate"', text)

    def test_allowlist_loop(self):
        self.env.loader = ChoiceLoader([
            DictLoader({'settings/allowed_ips.txt': (
                '# comment\n\n192.0.2.1\n  10.0.0.0/8  # LAN\n2001:db8::/32\n'
            )}), FileSystemLoader(ROOT),
        ])
        rendered = self.env.get_template('snippets/restrict.conf.jinja').render()
        self.assertEqual(rendered.splitlines(), [
            'allow 192.0.2.1;', 'allow 10.0.0.0/8;', 'allow 2001:db8::/32;', 'deny all;',
        ])
        self.env.loader = ChoiceLoader([
            DictLoader({'settings/allowed_ips.txt': '# no entries\n'}), FileSystemLoader(ROOT),
        ])
        self.assertEqual(self.env.get_template('snippets/restrict.conf.jinja').render().strip(), 'deny all;')

    def test_free_domain_loop(self):
        self.env.loader = ChoiceLoader([
            DictLoader({'settings/free_subdomains.txt': (
                '# suffixes\n\n  ddns.example.test # shared\nshared.example.test\nshared.example.co.uk\n'
            )}), FileSystemLoader(ROOT),
        ])
        rendered = self.env.get_template('conf.d/03_subdomain_upstream_map.conf.jinja').render()
        for suffix in ('ddns.example.test', 'shared.example.test', 'shared.example.co.uk'):
            expected = ('~^(?:.+[.])?(?<domain>[^.]+)[.]' + suffix.replace('.', '[.]')
                        + '$ ${domain}_' + suffix.replace('.', '_') + ';')
            self.assertIn(expected, rendered)
            self.assertLess(rendered.index(expected), rendered.index('(?<tld>'))
            pattern = expected.split()[0][1:].replace('(?<domain>', '(?P<domain>')
            for host in (f'tenant.{suffix}', f'app.tenant.{suffix}'):
                match = re.fullmatch(pattern, host)
                self.assertIsNotNone(match)
                self.assertEqual(match['domain'], 'tenant')
            self.assertIsNone(re.fullmatch(pattern, 'tenant.' + suffix.replace('.', 'X')))
        self.env.loader = ChoiceLoader([
            DictLoader({'settings/free_subdomains.txt': '# none\n'}), FileSystemLoader(ROOT),
        ])
        rendered = self.env.get_template('conf.d/03_subdomain_upstream_map.conf.jinja').render()
        self.assertNotIn('${domain}_ddns_example_test', rendered)
        self.assertIn('(?<tld>', rendered)

    def test_subfolder_regex_loop(self):
        self.env.loader = ChoiceLoader([
            DictLoader({'settings/subfolders.conf': (
                '# apps\n\nremote http://127.0.0.1:8000; # remote\n'
                '  media-center http://127.0.0.1:8001;\nremote-dev http://127.0.0.1:8002;\n'
            )}), FileSystemLoader(ROOT),
        ])
        rendered = self.env.get_template('conf.d/04_subfolder_upstream_map.conf.jinja').render()
        rule = next(line.strip() for line in rendered.splitlines() if line.strip().startswith('~^/'))
        pattern = re.compile(rule.split()[0][1:].replace('(?<subfolder_from_uri>', '(?P<subfolder_from_uri>'))
        for name in ('remote', 'media-center'):
            for suffix in ('', '-dev'):
                app = name + suffix
                for ending in ('', '/', '?x=1', '/path?x=1'):
                    match = pattern.match('/' + app + ending)
                    self.assertIsNotNone(match)
                    self.assertEqual(match['subfolder_from_uri'], app)
        for uri in ('/other/', '/remote-extra/', '/remote-dev-dev/', '/remotedev/', '/prefix/remote/'):
            self.assertIsNone(pattern.match(uri))
        self.env.loader = ChoiceLoader([
            DictLoader({'settings/subfolders.conf': '# no apps\n'}), FileSystemLoader(ROOT),
        ])
        rendered = self.env.get_template('conf.d/04_subfolder_upstream_map.conf.jinja').render()
        self.assertNotIn('~^/', rendered)
        self.assertIn('default "";', rendered)

    @unittest.skipUnless(shutil.which('nginx') and shutil.which('openssl'), 'nginx and openssl required')
    def test_nginx_complete_tree(self):
        with tempfile.TemporaryDirectory(prefix='router-hub-templates-') as temp:
            dest = Path(temp)
            context = dict(
                var_dir=str(dest / 'var'), router_ip='127.0.0.1',
                http_port=self.free_port(), https_port=self.free_port(),
                acme_challenge_dir=str(dest / 'acme'),
            )
            for directory in ('var/log/nginx', 'var/run', 'module.d', 'acme',
                              'certs/default', 'certs/example_test'):
                (dest / directory).mkdir(parents=True, exist_ok=True)
            # Render runtime includes separately; proxy aspects are expanded by Jinja
            # into each site and must never be rendered as shared runtime files.
            for source_name in ('nginx.conf.jinja', 'resolver.conf.jinja', 'mime.types', 'dhparams.pem'):
                (dest / source_name.removesuffix('.jinja')).write_text(
                    self.env.get_template(source_name).render(**context)
                )
            # Keep package-specific nginx temporary paths inside the lab fixture.
            main = dest / 'nginx.conf'
            main.write_text(main.read_text().replace('http {', 'http {\n' + '\n'.join(
                f'    {module}_temp_path {dest}/{module}-temp;'
                for module in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi')
            )))
            for directory in ('conf.d', 'settings', 'snippets', 'ban-shield'):
                (dest / directory).mkdir()
                for source in (ROOT / directory).iterdir():
                    if not source.name.endswith(('.conf', '.conf.jinja')):
                        continue
                    if directory == 'snippets' and source.name not in {
                        'ssl.conf.jinja', 'acme-challenge.conf.jinja', 'restrict.conf.jinja', 'security-headers.conf',
                                        }:
                        continue
                    (dest / directory / source.name.removesuffix('.jinja')).write_text(
                        self.env.get_template(f'{directory}/{source.name}').render(**context)
                    )
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(dest / 'certs/default/privkey.pem'),
                '-out', str(dest / 'certs/default/fullchain.pem'),
                '-days', '1', '-subj', '/CN=example.test',
            ], check=True, capture_output=True)
            for name in ('privkey.pem', 'fullchain.pem'):
                shutil.copy(dest / 'certs/default' / name, dest / 'certs/example_test' / name)
            # One root and subdomain per combination, each with a mounted subfolder.
            for index, bits in enumerate(itertools.product((False, True), repeat=len(FLAGS))):
                options = dict(context, **dict(zip(FLAGS, bits)), disable_root=False,
                               domain=f'site-{index}', subfolder='app')
                if isinstance(options.get('cache_policy'), bool):
                    options['cache_policy'] = 'no_cache' if options['cache_policy'] else 'inherit'
                site = dest / 'domains-enabled' / options['domain']
                (site / 'subfolders-enabled').mkdir(parents=True)
                (site / 'subdomains-enabled').mkdir()
                for kind, target, host in (
                    ('domain', site / 'root.conf', f'root-{index}.example.test'),
                    ('subdomain', site / 'subdomains-enabled/app.conf', f'app-{index}.example.test'),
                    ('subfolder', site / 'subfolders-enabled/app.conf', f'root-{index}.example.test'),
                ):
                    target.write_text(self.env.get_template(f'templates/{kind}.conf.jinja').render(
                        server_name=host, **options,
                    ))
            for index, bits in enumerate(itertools.product((False, True), repeat=3)):
                options = dict(context, cache_policy='pwa' if bits[0] else 'inherit', enable_restricted_sessions=bits[1],
                               clear_origin=bits[2], enable_lanonly=False, disable_root=False,
                               enable_large_upload=True, enable_longlived=True, enable_streaming=True,
                               domain=f'feature-{index}', subfolder='app')
                if isinstance(options.get('cache_policy'), bool):
                    options['cache_policy'] = 'no_cache' if options['cache_policy'] else 'inherit'
                site = dest / 'domains-enabled' / options['domain']
                (site / 'subfolders-enabled').mkdir(parents=True)
                (site / 'subdomains-enabled').mkdir()
                for kind, target, host in (
                    ('domain', site / 'root.conf', f'feature-root-{index}.example.test'),
                    ('subdomain', site / 'subdomains-enabled/app.conf', f'feature-app-{index}.example.test'),
                    ('subfolder', site / 'subfolders-enabled/app.conf', f'feature-root-{index}.example.test'),
                ):
                    target.write_text(self.env.get_template(f'templates/{kind}.conf.jinja').render(
                        server_name=host, **options,
                    ))
            for index, (name, options) in enumerate(PROFILES.items()):
                kind = name.split('/')[0]
                site = dest / f'domains-enabled/legacy-{index}'
                (site / 'subfolders-enabled').mkdir(parents=True)
                if kind == 'subfolder':
                    (site / 'root.conf').write_text(self.env.get_template('templates/domain.conf.jinja').render(
                        server_name=f'legacy-{index}.example.test', domain=f'legacy-{index}',
                        enable_lanonly=False, **context,
                    ))
                    target = site / 'subfolders-enabled/app.conf'
                else:
                    target = site / 'root.conf'
                target.write_text(self.env.get_template(f'templates/{kind}.conf.jinja').render(
                    server_name=f'legacy-{index}.example.test', domain=f'legacy-{index}',
                    subfolder='app', **context, **options,
                ))
            # Also verify the default domain (disabled root, enabled subfolders).
            default_site = dest / 'domains-enabled/default'
            default_site.mkdir()
            (default_site / 'root.conf').write_text(self.env.get_template('templates/domain.conf.jinja').render(
                server_name='default.example.test', domain='default', **context,
            ))
            result = subprocess.run(
                ['nginx', '-t', '-p', str(dest) + '/', '-c', 'nginx.conf', '-e', str(dest / 'syntax.log')],
                text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('suspicious symbols', result.stderr)
            print('nginx -t: 192 base combinations, 24 extra feature combinations, all 16 legacy variants passed')
            self.check_proxy_requests(dest, context['https_port'])

    @staticmethod
    def free_port():
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            return listener.getsockname()[1]

    def check_proxy_requests(self, dest, https_port):
        class Backend(BaseHTTPRequestHandler):
            requests = []

            def do_GET(self):
                self.requests.append((self.path, self.headers.get('Origin')))
                if self.headers.get('Upgrade') == 'websocket':
                    self.send_response(101)
                    self.send_header('Upgrade', 'websocket')
                    self.send_header('Connection', 'upgrade')
                    self.end_headers()
                else:
                    body = self.path.encode()
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        with HTTPServer(('127.0.0.1', 0), Backend) as backend:
            upstream = f'http://127.0.0.1:{backend.server_port}'
            # Index 0 has all optional aspects off; 62 has all on and is public.
            for name, prefix in (('domains.conf', 'root'), ('subdomains.conf', 'app')):
                (dest / 'settings' / name).write_text(''.join(
                    f'{prefix}-{index}.example.test {upstream};\n' for index in (0, 62)
                ) + f'feature-{prefix}-7.example.test {upstream};\n')
            (dest / 'settings/subfolders.conf').write_text(f'app {upstream};\n')
            # Re-render the derived URI map whenever the upstream names change.
            env = self.env.overlay(loader=ChoiceLoader([
                DictLoader({'settings/subfolders.conf': f'app {upstream};\n'}),
                FileSystemLoader(ROOT),
            ]))
            (dest / 'conf.d/04_subfolder_upstream_map.conf').write_text(
                env.get_template('conf.d/04_subfolder_upstream_map.conf.jinja').render()
            )
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            process = subprocess.Popen([
                'nginx', '-p', str(dest) + '/', '-c', 'nginx.conf',
                '-e', str(dest / 'runtime.log'),
            ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1', https_port), timeout=0.1):
                            break
                    except OSError:
                        pass
                    if process.poll() is not None:
                        self.fail(process.stderr.read())
                    time.sleep(0.02)
                else:
                    self.fail('nginx did not open its temporary listener')
                for index in (0, 62):
                    for host, prefix in ((f'root-{index}.example.test', ''),
                                         (f'app-{index}.example.test', ''),
                                         (f'root-{index}.example.test', '/app')):
                        with self.subTest(host=host, prefix=prefix):
                            connection = http.client.HTTPSConnection(
                                '127.0.0.1', https_port, timeout=3,
                                context=ssl._create_unverified_context(),
                            )
                            try:
                                connection.request('GET', prefix + '/hello?x=1', headers={'Host': host})
                                response = connection.getresponse()
                                self.assertEqual(response.status, 200)
                                self.assertEqual(response.read(), b'/hello?x=1')
                                self.assertEqual(response.getheader('X-Content-Type-Options'), 'nosniff')
                                if index == 62:
                                    self.assertIn('no-store', response.getheader('Cache-Control'))
                                connection.request('GET', prefix + '/socket', headers={
                                    'Host': host, 'Upgrade': 'websocket', 'Connection': 'upgrade',
                                })
                                response = connection.getresponse()
                                self.assertEqual(response.status, 101)
                                self.assertEqual(response.getheader('Upgrade'), 'websocket')
                                response.read()
                            finally:
                                connection.close()
                for host, prefix in (('feature-root-7.example.test', ''),
                                     ('feature-app-7.example.test', ''),
                                     ('feature-root-7.example.test', '/app')):
                    connection = http.client.HTTPSConnection(
                        '127.0.0.1', https_port, timeout=3, context=ssl._create_unverified_context(),
                    )
                    try:
                        for path, cache in (('/sw.js?v=1', 'no-store'),
                                            ('/index.html', 'no-store'),
                                            ('/manifest.webmanifest', 'no-store'),
                                            ('/service-worker.js', 'no-store'),
                                            ('/manifest.json', 'no-store'),
                                            ('/assets/main.js', 'max-age=31536000')):
                            connection.request('GET', prefix + path,
                                               headers={'Host': host, 'Origin': 'https://browser.example'})
                            response = connection.getresponse()
                            self.assertEqual(response.status, 200)
                            self.assertEqual(response.read(), path.encode())
                            self.assertIn(cache, response.getheader('Cache-Control'))
                            self.assertEqual(response.getheader('X-Content-Type-Options'), 'nosniff')
                            self.assertIsNone(Backend.requests[-1][1])
                        connection.request('GET', prefix + '/Sessions', headers={'Host': host})
                        response = connection.getresponse()
                        self.assertEqual(response.status, 403)
                        response.read()
                        connection.request('GET', prefix + '/socket', headers={
                            'Host': host, 'Connection': 'upgrade', 'Upgrade': 'websocket',
                        })
                        response = connection.getresponse()
                        self.assertEqual(response.status, 101)
                        response.read()
                    finally:
                        connection.close()
            finally:
                process.terminate()
                process.communicate(timeout=5)
                backend.shutdown()
                thread.join(timeout=5)
            print('Live nginx: routing, rewritten paths, security headers and WebSocket upgrades passed')


if __name__ == '__main__':
    unittest.main()
