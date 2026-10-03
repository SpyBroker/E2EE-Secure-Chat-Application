FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY protocol.py database.py storage.py crypto.py server.py ./

EXPOSE 65432
CMD ["python", "server.py", "0.0.0.0", "65432"]