#!/bin/sh
# Permissive entrypoint: first arg selects the component, rest are CLI args.
#
#   api     -> uvicorn app.api.main:app        (default)
#   cli ... -> python -m app.cli "$@"
#   spark   -> python spark_jobs/security_analytics.py "$@"
#   consumer-> python -m app.cli kafka-consumer "$@"
set -e

mode="${1:-api}"
case "$mode" in
  api)
    shift 2>/dev/null || true
    exec python -m uvicorn app.api.main:app --host 0.0.0.0 --port "${PORT:-8000}" "$@"
    ;;
  cli)
    shift
    exec python -m app.cli "$@"
    ;;
  consumer)
    shift
    exec python -m app.cli kafka-consumer "$@"
    ;;
  spark)
    shift
    exec python spark_jobs/security_analytics.py "$@"
    ;;
  *)
    # direct python entry
    exec python "$@"
    ;;
esac
