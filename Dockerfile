# Keystone service image (Ch. 63): one image, five roles chosen by command —
# api, admin, worker, anchor worker, beat — plus the provisioning init step.
# Multi-stage: the runtime layer holds the locked virtualenv and nothing that built it.

FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.28 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
# Dependencies first, so source edits do not invalidate the dependency layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY keystone ./keystone
COPY cli ./cli
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12-slim
RUN groupadd --system --gid 10001 keystone \
    && useradd --system --uid 10001 --gid keystone --no-create-home \
       --home-dir /nonexistent --shell /usr/sbin/nologin keystone
COPY --from=build /opt/venv /opt/venv
# Mount point for the rendered OPA config: a fresh named volume inherits this ownership, and
# 1000:1000 is the OPA image's user, which reads the file the opa-config init step writes.
RUN install -d -o 1000 -g 1000 -m 0755 /config
WORKDIR /app
COPY alembic.ini ./
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080 8081
# Liveness of the public plane; the admin and worker services override this in compose.
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
# --no-proxy-headers: uvicorn would otherwise trust X-Forwarded-For from 127.0.0.1; the only
# authority on the caller's address is KEYSTONE_TRUSTED_PROXIES (keystone.api.http.client_ip).
CMD ["uvicorn", "--factory", "keystone.api.app:app_from_env", "--host", "0.0.0.0", "--port", "8080", "--no-server-header", "--no-proxy-headers"]
