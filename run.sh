#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python 3 is required." >&2
  exit 1
fi

case "${1:-help}" in
  scan)
    shift
    if (($# == 0)); then set -- "${HOME}"; fi
    exec "$PYTHON" -m q_safe.cli scan "$@" --json reports/scan.jsonl
    ;;
  analyze)
    shift
    if (($# != 1)); then echo "Usage: ./run.sh analyze FILE" >&2; exit 2; fi
    exec "$PYTHON" -m q_safe.cli analyze "$1"
    ;;
  test)
    exec "$PYTHON" -m unittest discover -s tests -v
    ;;
  help|*)
    echo "Q-SAFE defensive CLI"
    echo "  ./run.sh scan [DIRECTORY ...]"
    echo "  ./run.sh analyze FILE"
    echo "  ./run.sh test"
    ;;
esac
