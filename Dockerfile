FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server/ .

RUN mkdir -p uploads

EXPOSE 5000

ENV ATOMICC2_ADMIN_TOKEN=ChangeThisAdminToken! \
    FLASK_SECRET_KEY=""

CMD ["python", "app.py"]
