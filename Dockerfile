FROM python:3.10-slim

WORKDIR /app

COPY server /app/server
RUN pip install --no-cache-dir -r /app/server/requirements.txt

EXPOSE 5000

CMD ["sh", "-c", "python3 /app/server/keygen.py & python3 /app/server/server.py"]
