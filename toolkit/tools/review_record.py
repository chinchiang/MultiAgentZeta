"""Keep the review record (〈定義：覆核紀錄〉) in step with GitHub.

    python3 -I toolkit/tools/review_record.py publish --record PATH --report REPORT --repo OWNER/NAME \
        --project SAMPLE [--new]
    python3 -I toolkit/tools/review_record.py sync --record PATH --roles PATH --roles-digest DIGEST \
        --repo OWNER/NAME --project SAMPLE

The GitHub token comes from MAZ_REVIEW_GITHUB_TOKEN; it is never printed or written. Both print the new
digest of the record on standard output, for the ScanManifest's review_record; a failure is reported on
standard error. The work is toolkit.review.main(); this file
only puts the repository on the path (-I leaves the working directory off it) and hands it GitHub.
"""
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

if __name__ == '__main__':
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from toolkit import github, review
    for stream in (sys.stdout, sys.stderr):  # -I ignores PYTHONIOENCODING; the messages carry non-ASCII paths
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    sys.exit(review.main(sys.argv[1:], os.environ, github.GitHub, sys.stdout, sys.stderr))
