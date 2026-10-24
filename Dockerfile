FROM python:3.11-slim

WORKDIR /app

# Prevent Python from writing .pyc files & buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Security: Create non-root dedicated user and group
RUN groupadd -r socgroup && useradd -r -g socgroup -d /app -s /sbin/nologin socuser

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Set appropriate directory permissions for non-root user
RUN mkdir -p /app/uploads && chown -R socuser:socgroup /app

# Switch to unprivileged user
USER socuser

# Expose port
EXPOSE 8000

# Container healthcheck
HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/stream/status || exit 1

# Run FastAPI via Uvicorn with production-ready flags
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
