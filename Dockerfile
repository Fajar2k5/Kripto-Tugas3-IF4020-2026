FROM python:3.13-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.7.5 /uv /usr/local/bin/uv
WORKDIR /opt/sleman
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.13-slim
COPY --from=build /opt/sleman/.venv /opt/sleman/.venv
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
ENTRYPOINT ["/opt/sleman/.venv/bin/sleman"]
