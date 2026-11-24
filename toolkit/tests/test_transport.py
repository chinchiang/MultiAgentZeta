"""toolkit.transport: the HTTP exchange and the command run in a container, without Docker.

The HTTP tests answer from a server on the loopback interface; the docker_exec tests replace subprocess.run.
"""
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from toolkit import transport


class _Handler(BaseHTTPRequestHandler):
    """Answers /redirect/<code> with that status and a Location to /target, and counts what reaches /target."""

    def _answer(self):
        self.server.seen.append((self.command, self.path, dict(self.headers)))
        if self.path.startswith('/redirect/'):
            self.send_response(int(self.path.rsplit('/', 1)[1]))
            self.send_header('Location', f'http://127.0.0.1:{self.server.server_port}/target')
            body = b'moved'
        else:
            self.send_response(200)
            body = b'[{"title": "TARGET"}]'
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PATCH = do_DELETE = _answer

    def log_message(self, *args):  # keep the test output quiet
        pass


class RedirectsAreNotFollowed(unittest.TestCase):
    """〈定義：測試結果〉 重新導向, TK-SBX-004: a 3xx is the answer; no second request is made."""

    def setUp(self):
        self.server = HTTPServer(('127.0.0.1', 0), _Handler)
        self.server.seen = []
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def test_a_redirect_is_answered_as_it_is(self):
        for method, code in (('GET', 301), ('GET', 302), ('GET', 303), ('GET', 307), ('GET', 308),
                             ('POST', 302), ('PATCH', 307), ('DELETE', 308)):
            with self.subTest(method=method, code=code):
                self.server.seen.clear()
                body = {'a': 1} if method in ('POST', 'PATCH') else None
                status, raw = transport.http(method, f'{self.base}/redirect/{code}',
                                             {'apikey': 'KEY', 'Authorization': 'Bearer TOKEN'}, body, 5)
                self.assertEqual((status, raw), (code, b'moved'))
                self.assertEqual([path for _, path, _ in self.server.seen], [f'/redirect/{code}'])

    def test_a_request_that_is_not_redirected_is_answered_as_before(self):
        status, raw = transport.http('GET', f'{self.base}/target', {'apikey': 'KEY'}, None, 5)
        self.assertEqual((status, raw), (200, b'[{"title": "TARGET"}]'))
        self.assertEqual(len(self.server.seen), 1)


class ValuesPassedIntoAContainer(unittest.TestCase):
    """TK-IDN-005: a value handed to docker_exec is not among the arguments of the host process."""

    def run_it(self, **kwargs):
        with mock.patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            transport.docker_exec('supabase_db_x', ['psql', '-c', 'select 1'], **kwargs)
        (argv,), options = run.call_args
        return argv, options

    def test_the_value_travels_in_the_environment_and_the_arguments_name_the_variable_only(self):
        argv, options = self.run_it(env={'PGPASSWORD': 'observer-secret'})
        self.assertEqual(argv, ['docker', 'exec', '-e', 'PGPASSWORD', 'supabase_db_x', 'psql', '-c', 'select 1'])
        self.assertNotIn('observer-secret', ' '.join(argv))
        self.assertEqual(options['env']['PGPASSWORD'], 'observer-secret')

    def test_the_rest_of_the_environment_is_kept_so_docker_still_finds_its_settings(self):
        with mock.patch.dict('os.environ', {'DOCKER_HOST': 'unix:///somewhere.sock'}):
            _, options = self.run_it(env={'PGPASSWORD': 'observer-secret'})
        self.assertEqual(options['env']['DOCKER_HOST'], 'unix:///somewhere.sock')

    def test_without_values_the_command_and_the_environment_are_untouched(self):
        argv, options = self.run_it(stdin='select 1;')
        self.assertEqual(argv, ['docker', 'exec', '-i', 'supabase_db_x', 'psql', '-c', 'select 1'])
        self.assertIsNone(options['env'])
        self.assertEqual(options['input'], 'select 1;')


if __name__ == '__main__':
    unittest.main()
