# backend/Dockerfile — hardened (multi-stage, non-root, prod deps only, no
# compiler/curl in the runtime layer).
#
# Build context is backend/ (the control plane), e.g.:
#   docker build -f backend/Dockerfile backend/
ARG PYTHON_IMAGE=python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf
FROM ${PYTHON_IMAGE} AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# Build-only toolchain: gcc + libpq (psycopg/asyncpg) and the xmlsec/libxml2
# headers python3-saml compiles against. None of this reaches the runtime image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libpq-dev libxml2-dev libxmlsec1-dev libxmlsec1-openssl pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY requirements-runtime.lock ./
COPY app ./app
COPY alembic.ini ./
COPY alembic ./alembic
# Dependencies come from the hashed lock, NOT from a floating resolution of
# pyproject. This image is the artifact security.yml Trivy-scans, SBOM-attests
# and cosign-signs — attesting an artifact whose contents were decided by
# whatever PyPI served at build time describes one machine's afternoon, however
# many signatures are wrapped around it. --require-hashes means every wheel here
# matches a hash committed to this repo, so a swapped or compromised upstream
# fails the build instead of being signed and shipped.
#
# requirements-runtime.lock, not requirements.lock: the runtime stage below does
# `COPY --from=builder /install /usr/local`, so anything installed here reaches
# production. The all-extras lock would put pytest, ruff, mypy and bandit in the
# shipped image. Runtime deps only — the header of this file is a promise.
#
# The application is copied as source into /app in the runtime stage, so there
# is deliberately no `pip install .` here. That would invoke PEP 517 build
# isolation and fetch floating setuptools/wheel build dependencies despite the
# runtime hash lock.
RUN pip install --prefix=/install --no-compile --require-hashes -r requirements-runtime.lock

FROM ${PYTHON_IMAGE} AS runtime
ARG PYTHON_IMAGE
LABEL org.opencontainers.image.base.name="${PYTHON_IMAGE}"
# Runtime shared libraries only (no -dev headers, no compiler): libpq for the
# DB driver, libxmlsec/libxml2 for SAML signature verification.
RUN groupadd -g 10001 app && useradd -u 10001 -g app -s /usr/sbin/nologin app \
 && apt-get update && apt-get install -y --no-install-recommends \
        libpq5 libxml2 libxmlsec1 libxmlsec1-openssl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /install /usr/local
WORKDIR /app
COPY --from=builder --chown=app:app /build/app ./app
COPY --from=builder --chown=app:app /build/alembic.ini ./alembic.ini
COPY --from=builder --chown=app:app /build/alembic ./alembic
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["python", "-c", \
  "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8000/v1/healthz', timeout=2); sys.exit(0 if r.status==200 else 1)"]
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", \
     "--port", "8000", "--no-server-header"]
