FROM python:3.11-slim

# >>> кэш-бастер версии билда
ARG APP_BUILD_REF=dev
LABEL org.opencontainers.image.revision=$APP_BUILD_REF

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-keep-alive", "5", "--limit-concurrency", "16"]
