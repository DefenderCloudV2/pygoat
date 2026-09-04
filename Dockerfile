FROM python:3.8

# set work directory
WORKDIR /app

# set environment variables
RUN apt-get update
RUN apt-get -y install dnsutils
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV SQLITE_PATH /tmp/db.sqlite3

# install dependencies
COPY requirements.txt requirements.txt
RUN pip install --use-deprecated=legacy-resolver -r requirements.txt

# copy project
COPY . /app/

RUN useradd --uid 10001 --create-home appuser
USER 10001

EXPOSE 8000

CMD ["sh", "-c", "test -f \"$SQLITE_PATH\" || cp pygoat/db.sqlite3 \"$SQLITE_PATH\"; python3 pygoat/manage.py migrate --noinput && python3 pygoat/manage.py runserver 0.0.0.0:8000"]
