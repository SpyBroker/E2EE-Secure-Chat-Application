# Lightweight Python base image
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY protocol.py database.py storage.py crypto.py server.py ./

# Expose Relay Server port
EXPOSE 65432

# Run Relay Server
CMD ["python", "server.py", "0.0.0.0", "65432"]
