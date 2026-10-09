FROM python:3.13-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libmagic1 postgresql-client tesseract-ocr tesseract-ocr-aze tesseract-ocr-eng tesseract-ocr-rus \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system bahar && useradd --system --gid bahar --home-dir /app bahar
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir \
    "alembic>=1.14,<2" \
    "boto3>=1.35,<2" \
    "cryptography>=44,<47" \
    "jsonschema>=4.23,<5" \
    "openpyxl>=3.1,<4" \
    "Pillow>=11,<13" \
    "psycopg[binary,pool]>=3.2,<4" \
    "PyMuPDF>=1.25,<2" \
    "SQLAlchemy>=2.0,<3"
COPY README.md ./
COPY src ./src
COPY data ./data
COPY web ./web
COPY alembic.ini ./
COPY migrations ./migrations
RUN pip install --no-cache-dir --no-deps .
USER bahar
EXPOSE 8088
ENTRYPOINT []
