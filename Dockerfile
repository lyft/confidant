FROM ubuntu:trusty
LABEL maintainer="rlane@lyft.com"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && /usr/bin/curl -sL --fail https://deb.nodesource.com/setup_8.x | bash -
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        # For frontend
        make ruby-dev nodejs git-core \
        # For backend
        gcc pkg-config \
        python-dev python-virtualenv \
        libffi-dev libxml2-dev libxmlsec1-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY ./piptools_requirements.txt /srv/confidant/piptools_requirements.txt
COPY ./requirements.txt /srv/confidant/requirements.txt
COPY ./package.json /srv/confidant/package.json
COPY ./bower.json /srv/confidant/bower.json

WORKDIR /srv/confidant

ENV PATH=/venv/bin:$PATH
RUN virtualenv /venv && \
    pip install --upgrade pip && \
    pip install -r piptools_requirements.txt && \
    pip install -r requirements.txt

RUN gem install rb-inotify -v 0.9.10 && \
    gem install compass -v 1.0.3 && \
    npm install grunt-cli && \
    npm install

COPY . /srv/confidant

RUN node_modules/grunt-cli/bin/grunt build

EXPOSE 80

CMD ["gunicorn", "confidant.wsgi:app", "--workers=2", "-k", "gevent", "--access-logfile=-", "--error-logfile=-"]
