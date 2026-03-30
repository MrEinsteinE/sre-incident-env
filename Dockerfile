FROM python:3.11-slim

WORKDIR /app

# Dependencies first — maximizes layer cache on rebuilds
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY tasks.py      .
COPY graders.py    .
COPY openenv.yaml  .
COPY inference.py  .
COPY server/       ./server/

RUN touch server/__init__.py

EXPOSE 7860
ENV PYTHONPATH=/app

# Healthcheck so HF knows the container is genuinely ready
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7860/health')" || exit 1

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
