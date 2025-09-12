# Ubuntu-based image that serves the crypto_list web app (FastAPI/uvicorn).
# Includes python3-tk so the image has Tkinter available (even though we launch the web app).

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System dependencies: Python, pip, Tkinter, and CA certs
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-tk \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md LICENSE /app/
COPY crypto_list /app/crypto_list

# Install Python dependencies and this package
RUN python3 -m pip install --no-cache-dir --upgrade pip && \
    python3 -m pip install --no-cache-dir .

# Expose the web app port
EXPOSE 8000

# Default: run the FastAPI web app using the installed console script
CMD ["crypto-list-webapp", "--host", "0.0.0.0", "--port", "8000"]
