FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN pip install uv && uv sync --frozen --no-dev

EXPOSE 8443

CMD ["uv", "run", "python", "-m", "azure_keyvault_docker"]
