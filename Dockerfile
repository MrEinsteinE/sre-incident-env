FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install Python dependencies first (maximizes Docker layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY tasks.py      .
COPY graders.py    .
COPY openenv.yaml  .
COPY inference.py  .
COPY server/       ./server/

# Ensure server is a Python package
RUN touch server/__init__.py

# HuggingFace Spaces requires port 7860
EXPOSE 7860

# Add project root to Python path
ENV PYTHONPATH=/app

# Start the FastAPI server
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
