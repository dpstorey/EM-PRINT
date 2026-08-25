# Multi-stage build, mirrors EM-MCP's Dockerfile pattern.
FROM python:3.12.7-slim-bookworm AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
RUN pip install --upgrade pip==24.3.1
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip wheel --wheel-dir /wheels .

FROM python:3.12.7-slim-bookworm

LABEL org.opencontainers.image.title="Tenable OT Print Report MCP Server"
LABEL org.opencontainers.image.description="MCP server generating Tenable OT print reports to a mounted filestore."

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MCP_DATA_DIR=/data \
    MCP_OUTPUT_DIR=/output \
    MCP_BIND_HOST=0.0.0.0 \
    MCP_BIND_PORT=40444

RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 mcp && \
    useradd -u 1000 -g 1000 -d /home/mcp -m -s /bin/bash mcp && \
    mkdir -p /data /output && chown -R 1000:1000 /data /output

COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links=/wheels tenable-ot-print-mcp && rm -rf /wheels

USER 1000
WORKDIR /home/mcp

VOLUME ["/data", "/output"]
EXPOSE 40444

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import ssl, urllib.request, sys; ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; sys.exit(0 if urllib.request.urlopen('https://127.0.0.1:40444/healthz', timeout=3, context=ctx).status == 200 else 1)"

ENTRYPOINT ["tenable-ot-print-mcp"]
CMD ["serve"]
