# VulnHealer Production Dockerfile
# Multi-stage build for optimized image size

# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime image
FROM python:3.11-slim AS runtime

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    nodejs \
    npm \
    default-jdk \
    gcc \
    g++ \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep globally
RUN pip install --no-cache-dir semgrep

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Ensure Python packages are in PATH
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY . /app/

# Create data directory
RUN mkdir -p /app/data

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default command
CMD ["streamlit", "run", "ui/streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0"]
