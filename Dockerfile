FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN apt-get update && apt-get install -y nodejs npm
CMD ["sh", "-c", "python app/main.py & node-red --userDir /data"]