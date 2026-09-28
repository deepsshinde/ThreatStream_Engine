# ThreatStream Engine - all-in-one image (API + pipeline + Spark deps)
#
# Build:  docker build -t threatstream:2.0 .
# Run:    docker compose up -d
# CLI:    docker run --rm threatstream:2.0 process-file sample_logs/cloudtrail.json
#
# The image keeps dependencies on a normal laptop budget (~8-16GB RAM):
# we install the pinned requirements with --no-cache-dir and no optional ML
# extras beyond what requirements.txt lists (sentence-transformers brings
# torch CPU via its default extras; for the slim image use requirements-slim.txt).
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/threatstream

# Java runtime for PySpark (headless JRE; spark specials fall back without it)
RUN apt-get update \
 && apt-get install -y --no-install-recommends default-jre-headless ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# ---- dependency layer (cached unless requirements change) ----
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ---- application layer ----
COPY app ./app
COPY config ./config
COPY db ./db
COPY frontend ./frontend
COPY spark_jobs ./spark_jobs
COPY sample_logs ./sample_logs
COPY scripts ./scripts
COPY docker-entrypoint.sh ./docker-entrypoint.sh

RUN chmod +x docker-entrypoint.sh && useradd -r -u 10001 ts && chown -R ts:ts /opt/threatstream
USER ts

EXPOSE 8000

# default: run the API; override command for CLI usage (see entrypoint)
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["api"]
