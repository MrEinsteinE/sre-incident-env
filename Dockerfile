FROM python:3.11-slim

WORKDIR /app

# Install dependencies first — maximizes Docker layer cache on rebuilds
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application source
COPY tasks.py      .
COPY graders.py    .
COPY openenv.yaml  .
COPY inference.py  .
COPY server/       ./server/

# Ensure server package is importable
RUN test -f server/__init__.py || touch server/__init__.py

EXPOSE 7860

# Project root on path so tasks.py / graders.py are importable everywhere
ENV PYTHONPATH=/app

# Healthcheck: poll /health until the server is accepting connections
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7860/health')" || exit 1

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]