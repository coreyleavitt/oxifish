FROM python:3.12-slim

# Install Rust
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

# Install uv and maturin
RUN pip install --no-cache-dir uv && \
    uv pip install --system maturin

WORKDIR /app

# Copy project files
COPY Cargo.toml pyproject.toml uv.lock README.md ./
COPY src/ ./src/
COPY python/ ./python/
COPY tests/ ./tests/

# Install dev dependencies and build extension
RUN uv sync --dev && \
    uv run mypy tests/ --strict && \
    uv run pytest tests/ -v
