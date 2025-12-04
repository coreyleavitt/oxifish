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
    uv pip install --system maturin pytest

WORKDIR /app

# Copy project files
COPY Cargo.toml pyproject.toml README.md ./
COPY src/ ./src/
COPY python/ ./python/
COPY tests/ ./tests/

# Build the extension
RUN maturin build --release

# Install the wheel and run tests
RUN pip install target/wheels/*.whl && \
    pytest tests/ -v
