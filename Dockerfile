# Multi-stage build for Voxcord production deployment
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_ENV=production

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    gcc \
    g++ \
    gfortran \
    libopenblas-dev \
    liblapack-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install wheel first
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install numpy first to avoid compilation issues
RUN pip install --no-cache-dir numpy==1.24.3

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8080 \
    PYTHONPATH=/app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    libopenblas0 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r voxcord \
    && useradd -r -g voxcord voxcord

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create app directory
WORKDIR /app

# Copy application code
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p static audio_files logs \
    && touch voxcord.db \
    && chown -R voxcord:voxcord /app

# Switch to non-root user
USER voxcord

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:$PORT/api/health || exit 1

# Expose port
EXPOSE $PORT

# Default command - can be overridden by Digital Ocean
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:application"]
