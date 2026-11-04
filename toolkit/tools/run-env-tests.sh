#!/bin/sh
# Run the environment tests (MAZ_ENV_TESTS=1) detached from this shell, or show a run's progress.
#
#   toolkit/tools/run-env-tests.sh NAME [-p PATTERN] [-k NAME_FILTER ...]   # log: scratch/logs/NAME.log
#   toolkit/tools/run-env-tests.sh --status NAME
#
# Details (detaching, the lock, leftover Docker resources, the log format): toolkit/tools/env_tests.py.
exec python3 -I "$(dirname "$0")/env_tests.py" "$@"
