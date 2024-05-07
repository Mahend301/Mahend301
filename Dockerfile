FROM python:3.9.13-alpine

WORKDIR /usr/src/app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
RUN apk --update add python3 py3-pip python3-dev


RUN apk update \
    && apk add postgresql-dev gcc musl-dev

RUN pip install --upgrade pip
COPY ./requirements.txt .

RUN pip install -r requirements.txt --no-cache-dir

COPY . .