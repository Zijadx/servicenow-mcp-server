FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY server.py .
COPY security_analyst.py .

# Don't copy .env — secrets come in via environment variables at runtime
# Port exposed by uvicorn
EXPOSE 8000

# Run in streamable-http mode (required for Docker/Railway)
ENV MCP_TRANSPORT=streamable-http

CMD ["python", "server.py"]
