FROM python:3.13-slim

RUN useradd --create-home --shell /usr/sbin/nologin sandbox

WORKDIR /workspace
COPY infra/sandbox/entrypoint.py /usr/local/bin/devbox-sandbox
RUN chmod 0755 /usr/local/bin/devbox-sandbox

USER sandbox
ENTRYPOINT ["python", "/usr/local/bin/devbox-sandbox"]
