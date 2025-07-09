FROM python:3.9-slim

WORKDIR /app
COPY main.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Expose the port Render assigns (defaults to 10000)
EXPOSE $PORT

CMD ["python", "main.py"]