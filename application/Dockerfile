FROM python:3.10-slim AS builder

WORKDIR /build

COPY requirements.txt .

RUN pip install \
    --no-cache-dir \
    --target=/build/deps \
    -r requirements.txt


FROM gcr.io/distroless/python3-debian13:nonroot

WORKDIR /app

COPY --from=builder /build/deps /app/deps
COPY app.py /app/app.py

ENV PYTHONPATH=/app/deps
ENV FLASK_HOST=0.0.0.0

EXPOSE 5000

CMD ["python", "app.py"]