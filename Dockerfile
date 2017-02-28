FROM python:2-alpine
MAINTAINER Ryan Lane <rlane@lyft.com>

WORKDIR /srv/confidant

COPY ./piptools_requirements.txt piptools_requirements.txt
COPY ./requirements.txt requirements.txt
COPY ./package.json package.json
COPY ./bower.json bower.json

RUN apk add --no-cache ruby nodejs git libffi ca-certificates py-libxslt libltdl xmlsec openssl
RUN apk add --no-cache --virtual .build-deps ruby-dev build-base libffi-dev libxml2-dev xmlsec-dev openssl-dev && \
    pip install --no-cache-dir -r piptools_requirements.txt -r requirements.txt && \
    gem install --no-ri --no-rdoc compass && \
    npm install grunt-cli && \
    npm install && \
    apk del --no-cache .build-deps

COPY . .

RUN node_modules/grunt-cli/bin/grunt build

EXPOSE 80

CMD ["gunicorn","confidant.wsgi:app","--workers=2","-k","gevent","--access-logfile=-","--error-logfile=-"]
