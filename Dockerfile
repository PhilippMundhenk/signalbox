# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

FROM python:3.13-slim
ARG VERSION=dev
ARG EXTRA_PACKAGES=""
LABEL org.opencontainers.image.title="Signalbox" \
      org.opencontainers.image.description="See, check and configure every device of a small office or home network" \
      org.opencontainers.image.source="https://github.com/PhilippMundhenk/signalbox" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
RUN if [ -n "$EXTRA_PACKAGES" ]; then \
      apt-get update && apt-get install -y --no-install-recommends $EXTRA_PACKAGES \
      && rm -rf /var/lib/apt/lists/*; fi
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl \
    && useradd --system --uid 10001 --home-dir /data signalbox \
    && mkdir /data && chown signalbox /data
USER signalbox
ENV SIGNALBOX_DATA=/data \
    SIGNALBOX_SERVER_PORT=8080 \
    PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('SIGNALBOX_SERVER_PORT','8080'),timeout=3)"]
ENTRYPOINT ["signalbox"]
CMD ["serve"]
