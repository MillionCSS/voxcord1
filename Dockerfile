# Multi-stage production Dockerfile for Voxcord
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install wheel
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"
ENV PORT=8080
ENV FLASK_ENV=production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r voxcord \
    && useradd -r -g voxcord voxcord

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set work directory
WORKDIR /app

# Copy application code
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p static audio_files logs \
    && touch voxcord.log \
    && chown -R voxcord:voxcord /app

# Switch to non-root user
USER voxcord

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:$PORT/api/health || exit 1

# Expose port
EXPOSE $PORT

# Default command
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--worker-class", "gevent", "--worker-connections", "1000", "--timeout", "120", "--keepalive", "5", "--max-requests", "1000", "--max-requests-jitter", "50", "--preload", "production_voxcord_backend:app"]
