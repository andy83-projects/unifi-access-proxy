FROM python:3.12-alpine

LABEL org.opencontainers.image.title="unifi-access-proxy" \
      org.opencontainers.image.description="Software emulator and bridge for UniFi Access (UA-Hub)" \
      org.opencontainers.image.source="https://github.com/andy83-projects/unifi-access-proxy"

WORKDIR /app

# Copy source
COPY src/ /app/src/

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1

EXPOSE 10001/udp 8000/tcp

USER 1000:1000

ENTRYPOINT ["python3", "-m", "unifi_access_proxy"]
