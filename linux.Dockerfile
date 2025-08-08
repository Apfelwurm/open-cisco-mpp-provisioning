FROM python:3.13-slim

WORKDIR /app

ARG BUILDNODE=unspecified
ENV BUILDNODE=$BUILDNODE
ARG SOURCE_COMMIT=unspecified
ENV SOURCE_COMMIT=$SOURCE_COMMIT

LABEL com.apfelwurm.build-node=$BUILDNODE `
      org.label-schema.schema-version="1.0" `
      org.label-schema.url="https://volzit.de" `
      org.label-schema.vcs-ref=$SOURCE_COMMIT `
      org.label-schema.vendor="volzit" `
      org.label-schema.description="Docker-based HTTP service that provides dynamic XML configuration provisioning for Cisco Multiplatform Phones (MPP)" `
      org.label-schema.vcs-url="https://github.com/Apfelwurm/open-cisco-mpp-provisioning"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs config

# Set permissions
RUN chmod +x app.py

EXPOSE 8080

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Use gunicorn for production serving
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "2", "-k", "gthread", "--threads", "4", "--timeout", "120", "app:app"]
