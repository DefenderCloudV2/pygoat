FROM python:3.8

# set work directory
WORKDIR /app

# set environment variables
RUN apt-get update \
    && apt-get install --no-install-recommends -y dnsutils=1:9.18.49-1~deb12u2 \
    && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SQLITE_PATH=/tmp/db.sqlite3

# install dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir setuptools==60.10.0 wheel==0.45.1 \
    && pip install --no-cache-dir --no-build-isolation --use-deprecated=legacy-resolver -r requirements.txt

# copy project
COPY . /app/

RUN useradd --uid 10001 --create-home appuser
USER 10001

EXPOSE 8000

CMD ["sh", "-c", "python3 manage.py migrate --noinput && python3 manage.py runserver 0.0.0.0:8000"]
