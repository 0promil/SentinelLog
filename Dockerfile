FROM python:3.11-slim

WORKDIR /app


RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .


COPY entrypoint.sh .
RUN chmod +x entrypoint.sh


EXPOSE 8000


CMD ["./entrypoint.sh"]

