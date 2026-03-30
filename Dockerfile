FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tasks.py .
COPY graders.py .
COPY openenv.yaml .
COPY inference.py .
COPY server/ ./server/

RUN touch server/__init__.py

EXPOSE 7860
ENV PYTHONPATH=/app

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
