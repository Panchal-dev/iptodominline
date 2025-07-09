FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Install dependencies for system reboot (if needed)
RUN apt-get update && apt-get install -y systemd && apt-get clean

# Set environment variable for Render webhook (optional)
ENV RENDER_WEBHOOK_URL=""

CMD ["python", "main.py"]