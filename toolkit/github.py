"""GitHub as the platform of the review record (〈定義：覆核紀錄〉): the platform seam toolkit.review uses.

It reports what GitHub's REST API reports (design notes [R61]) as toolkit.review's LabelEvent and
Comment, and decides nothing: which events are decisions is toolkit.review's to say.
"""
import json
import urllib.error
import urllib.request

from toolkit.review import Comment, LabelEvent, PlatformError

API = 'https://api.github.com'
API_VERSION = '2022-11-28'  # the REST API version [R61] describes


TIMEOUT = 30  # seconds per request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is answered as it is: urllib would send the Authorization header on to wherever it points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def urllib_transport(method, url, headers, body):
    """(status, headers, body) of one HTTP request; an error status is answered, not raised, for the caller
    to judge, and so is a redirect, which is never followed. A request that gets no answer raises OSError."""
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    if body is not None:
        request.add_header('Content-Type', 'application/json')
    try:
        with _OPENER.open(request, timeout=TIMEOUT) as answer:
            return answer.status, dict(answer.headers), answer.read()
    except urllib.error.HTTPError as e:
        with e:
            return e.code, dict(e.headers), e.read()


def _next_page(link):
    """The URL of rel="next" in a Link header, or None."""
    for part in link.split(','):
        target, _, params = part.partition(';')
        if 'rel="next"' in params:
            return target.strip().strip('<>')
    return None


class GitHub:
    """The issues of one repository. transport(method, url, headers, body) -> (status, headers, body) does
    the HTTP; tests give one that replays fixtures."""

    def __init__(self, repo, token, transport=urllib_transport):
        self.repo, self.token, self.transport = repo, token, transport

    def _send(self, method, url, body=None):
        """(headers, parsed JSON body) of one request that GitHub answered with a 2xx status. The token goes
        to the GitHub API only: a URL elsewhere, even one GitHub's own Link header names, is the platform's
        error."""
        if not url.startswith(API + '/'):
            raise PlatformError(f'{url} is not on {API}; the token is not sent there')
        headers = {'Authorization': f'Bearer {self.token}', 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': API_VERSION}
        try:
            status, answer_headers, answer = self.transport(method, url, headers, body)
        except OSError as e:
            raise PlatformError(f'{method} {url}: no answer from GitHub ({e})') from e
        if not 200 <= status < 300:
            raise PlatformError(f'{method} {url}: GitHub answered {status}: {answer[:200]!r}')
        try:
            return answer_headers, json.loads(answer)
        except ValueError as e:
            raise PlatformError(f'{method} {url}: GitHub answered something that is not JSON') from e

    def _get(self, path):
        """Every item of a list, page after page as the Link header's next names them."""
        url, items = f'{API}/repos/{self.repo}{path}?per_page=100', []
        while url:
            headers, page = self._send('GET', url)
            if not isinstance(page, list):
                raise PlatformError(f'GET {url}: GitHub answered no list')
            items += page
            url = _next_page(headers.get('Link', ''))
        return items

    def label_events(self, number):
        """The labels added to and removed from the issue, as LabelEvent."""
        events = self._get(f'/issues/{number}/events')
        try:
            return [LabelEvent(id=e['id'], action=e['event'], actor_id=e['actor']['id'],
                               actor_login=e['actor']['login'], label=e['label']['name'], at=e['created_at'])
                    for e in events if e['event'] in ('labeled', 'unlabeled')]
        except (KeyError, TypeError) as e:
            raise PlatformError(f'issue {number}: a label event lacks {e}') from e

    def comments(self, number):
        """The comments on the issue, as Comment; their text is only ever kept as a reason."""
        comments = self._get(f'/issues/{number}/comments')
        try:
            return [Comment(id=c['id'], author_id=c['user']['id'], author_login=c['user']['login'], body=c['body'],
                            created_at=c['created_at'], updated_at=c['updated_at']) for c in comments]
        except (KeyError, TypeError) as e:
            raise PlatformError(f'issue {number}: a comment lacks {e}') from e

    def create_issue(self, title, body):
        """Open an issue and return its number, which the review record keeps (〈定義：覆核紀錄〉 工單)."""
        url = f'{API}/repos/{self.repo}/issues'
        _, created = self._send('POST', url, json.dumps({'title': title, 'body': body}).encode())
        if not (isinstance(created, dict) and isinstance(created.get('number'), int)):
            raise PlatformError(f'POST {url}: GitHub answered no issue number')
        return created['number']
