#!/bin/sh
# Run the environment tests (MAZ_ENV_TESTS=1) detached from this shell, or show a run's progress.
#
#   toolkit/tools/run-env-tests.sh NAME [-p PATTERN] [-k NAME_FILTER ...]   # log: scratch/logs/NAME.log
#   toolkit/tools/run-env-tests.sh --status NAME
#
# Runs with the repository's .venv/bin/python when it is runnable (it holds the packages of
# toolkit/requirements.lock; no need to activate it, and it wins over any other active environment),
# otherwise with python3 from PATH.
# Details (detaching, the lock, leftover Docker resources, the log format): toolkit/tools/env_tests.py.
here=$(cd "$(dirname "$0")" && pwd)
py="$here/../../.venv/bin/python"
[ -x "$py" ] || py=python3
exec "$py" -I "$here/env_tests.py" "$@"
