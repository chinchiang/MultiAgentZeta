"""The GitHub adapter of the platform seam (〈定義：覆核紀錄〉): what GitHub's REST API reports, as
toolkit.review's LabelEvent and Comment.

The responses in fixtures/github are written by hand in the shape GitHub's documentation gives
(design notes [R61]), not recorded from GitHub; the integration test against GitHub itself is #22's.
"""
import json
import unittest
from pathlib import Path

from toolkit import github, review

FIXTURES = Path(__file__).with_name('fixtures') / 'github'
API = 'https://api.github.com/repos/owner/reviews'


def recorded(name):
    return (FIXTURES / name).read_bytes()


class Replay:
    """An HTTP transport that answers from fixtures and remembers what was asked."""

    def __init__(self, answers):
        self.answers, self.asked = answers, []  # (method, url) -> (status, headers, body)

    def __call__(self, method, url, headers, body):
        self.asked.append((method, url, headers, body))
        return self.answers[(method, url)]


class LabelEvents(unittest.TestCase):

    def test_labels_added_and_removed_become_label_events_and_nothing_else_does(self):
        replay = Replay({('GET', f'{API}/issues/7/events?per_page=100'):
                         (200, {}, recorded('issue-7-events-page-1.json'))})
        events = github.GitHub('owner/reviews', 'token-x', transport=replay).label_events(7)
        self.assertEqual(events, [
            review.LabelEvent(id=9001, action='labeled', actor_id=101, actor_login='sec-alice',
                              label='review:reject', at='2026-11-09T03:00:00Z'),
            review.LabelEvent(id=9003, action='unlabeled', actor_id=101, actor_login='sec-alice',
                              label='review:reject', at='2026-11-09T03:20:00Z')])


    def test_the_events_continue_on_the_next_page_the_link_header_names(self):
        page2 = 'https://api.github.com/repositories/42/issues/7/events?per_page=100&page=2'
        link = f'<{page2}>; rel="next", <{page2}>; rel="last"'
        replay = Replay({('GET', f'{API}/issues/7/events?per_page=100'):
                         (200, {'Link': link}, recorded('issue-7-events-page-1.json')),
                         ('GET', page2): (200, {'Link': f'<{API}/issues/7/events?per_page=100>; rel="first"'},
                                          recorded('issue-7-events-page-2.json'))})
        events = github.GitHub('owner/reviews', 'token-x', transport=replay).label_events(7)
        self.assertEqual([e.id for e in events], [9001, 9003, 9004])
        self.assertEqual(len(replay.asked), 2)



class Comments(unittest.TestCase):

    def test_comments_become_comments_with_their_author_and_times(self):
        replay = Replay({('GET', f'{API}/issues/7/comments?per_page=100'):
                         (200, {}, recorded('issue-7-comments.json'))})
        self.assertEqual(github.GitHub('owner/reviews', 'token-x', transport=replay).comments(7), [
            review.Comment(id=5001, author_id=101, author_login='sec-alice',
                           body="the other tenant's row came back; the leak is real",
                           created_at='2026-11-09T02:30:00Z', updated_at='2026-11-09T02:35:00Z')])


class CreateIssue(unittest.TestCase):

    def test_an_issue_is_opened_with_its_title_and_body_and_its_number_returned(self):
        replay = Replay({('POST', f'{API}/issues'): (201, {}, recorded('issue-created.json'))})
        number = github.GitHub('owner/reviews', 'token-x', transport=replay).create_issue('a title', 'a body')
        self.assertEqual(number, 12)
        (_, _, _, sent), = replay.asked
        self.assertEqual(json.loads(sent), {'title': 'a title', 'body': 'a body'})


class Requests(unittest.TestCase):
    """What the adapter sends: the token and the API version it was written for ([R61])."""

    def test_every_request_carries_the_token_and_the_api_version(self):
        replay = Replay({('GET', f'{API}/issues/7/events?per_page=100'): (200, {}, b'[]')})
        github.GitHub('owner/reviews', 'token-x', transport=replay).label_events(7)
        (_, _, headers, _), = replay.asked
        self.assertEqual((headers['Authorization'], headers['X-GitHub-Api-Version'], headers['Accept']),
                         ('Bearer token-x', '2022-11-28', 'application/vnd.github+json'))

    def test_a_next_page_on_another_host_is_not_followed_with_the_token(self):
        link = '<https://evil.example/repos/owner/reviews/issues/7/events?page=2>; rel="next"'
        replay = Replay({('GET', f'{API}/issues/7/events?per_page=100'): (200, {'Link': link}, b'[]')})
        with self.assertRaises(review.PlatformError):
            github.GitHub('owner/reviews', 'token-x', transport=replay).label_events(7)
        self.assertEqual([u for _, u, _, _ in replay.asked], [f'{API}/issues/7/events?per_page=100'])



class Errors(unittest.TestCase):
    """Whatever goes wrong talking to GitHub is a PlatformError, which toolkit.review handles as 同步失敗."""

    URL = f'{API}/issues/7/events?per_page=100'

    def test_what_github_does_not_answer_properly_is_a_platform_error(self):
        def unreachable(*_):
            raise OSError('connection refused')
        answers = {'an error status': Replay({('GET', self.URL): (502, {}, b'{"message": "Bad Gateway"}')}),
                   'a redirect': Replay({('GET', self.URL): (301, {'Location': 'https://evil.example/'}, b'')}),
                   'a body that is not JSON': Replay({('GET', self.URL): (200, {}, b'<html>')}),
                   'an event without its actor': Replay({('GET', self.URL): (200, {}, json.dumps(
                       [{'id': 1, 'event': 'labeled', 'label': {'name': 'x'}, 'created_at': 't'}]).encode())}),
                   'no answer at all': unreachable}
        for name, transport in answers.items():
            with self.subTest(name):
                with self.assertRaises(review.PlatformError):
                    github.GitHub('owner/reviews', 'token-x', transport=transport).label_events(7)



class UrllibTransport(unittest.TestCase):
    """The transport used against GitHub itself, tried on a loopback server (no network)."""

    def test_an_error_status_is_answered_not_raised(self):
        from toolkit.tests.test_scan import one_reply_server
        url = one_reply_server(b'HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 2\r\n'
                               b'Link: <x>; rel="next"\r\n\r\n{}')
        status, headers, body = github.urllib_transport('GET', url + '/repos/x', {'Accept': 'application/json'}, None)
        self.assertEqual((status, headers.get('Link'), body), (404, '<x>; rel="next"', b'{}'))


    def test_a_redirect_is_answered_not_followed_with_the_token(self):
        # urllib would copy the Authorization header to wherever a 3xx points (〈定義：覆核紀錄〉 身分).
        import socket
        import threading
        from toolkit.tests.test_scan import one_reply_server
        elsewhere, contacted = socket.socket(), []
        elsewhere.bind(('127.0.0.1', 0))
        elsewhere.listen(1)
        elsewhere.settimeout(2)

        def watch():
            try:
                conn, _ = elsewhere.accept()
                contacted.append(conn.recv(65536))
                conn.close()
            except OSError:
                pass
        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        target = f'http://127.0.0.1:{elsewhere.getsockname()[1]}/stolen'
        url = one_reply_server(f'HTTP/1.1 301 Moved Permanently\r\nLocation: {target}\r\nContent-Length: 0\r\n\r\n'
                               .encode())
        status, headers, _ = github.urllib_transport('GET', url + '/repos/x', {'Authorization': 'Bearer t'}, None)
        watcher.join()
        elsewhere.close()
        self.assertEqual((status, headers.get('Location')), (301, target))
        self.assertEqual(contacted, [])


if __name__ == '__main__':
    unittest.main()
