# syntax=docker/dockerfile:1
# check=skip=JSONArgsRecommended,MultipleInstructionsDisallowed

FROM python:3.10-slim

WORKDIR /app

# curl is the only runtime dep needed (Docker healthcheck).
# torch/transformers/spacy all ship pre-built wheels so build-essential is not required.
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends --fix-missing curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --retries 5 -r requirements.txt

# Download NLTK data
RUN python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"

COPY . .

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]
