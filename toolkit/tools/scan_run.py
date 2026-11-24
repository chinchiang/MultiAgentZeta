"""Run one scan (〈定義：命令列入口〉): the toolkit's one outward action, from the command line.

    python3 -I toolkit/tools/scan_run.py --manifest MANIFEST.json --out REPORT_DIR

Reads the ScanManifest, runs it against the E1 stack of its target project, and writes REPORT_DIR/report.json
and REPORT_DIR/report.md. REPORT_DIR must be outside the source under test and hold no earlier report. The
run needs Docker and the Supabase CLI of the support matrix (MAZ_SUPABASE_BIN, see fetch-supabase-cli.sh).

Exit status: 0 a report was written, whatever the run's status (completed, partial or blocked: read the
status line or the report); 2 the command line, the ScanManifest file or the output directory was refused and
nothing was started; 3 the toolkit itself failed. The status goes to standard output, refusals and failures
to standard error. The work is toolkit.scan.main(); this file only puts the repository on the path (-I
leaves the working directory off it).
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

if __name__ == '__main__':
    for stream in (sys.stdout, sys.stderr):  # -I ignores PYTHONIOENCODING; the status line is not all ASCII
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from toolkit import scan
    sys.exit(scan.main(sys.argv[1:], sys.stdout, sys.stderr))
