FROM ubuntu:jammy
LABEL maintainer="rlane@lyft.com"

WORKDIR /srv/confidant

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && /usr/bin/curl -sL --fail https://deb.nodesource.com/setup_18.x | bash -
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        # For frontend
        make nodejs git-core \
        # For backend
        gcc pkg-config \
        python3.10-dev virtualenv \
        libffi-dev libxml2-dev libxmlsec1-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY package.json /srv/confidant/

RUN npm install grunt-cli && \
    npm install

COPY piptools_requirements.txt requirements.txt /srv/confidant/

ENV PATH=/venv/bin:$PATH
RUN virtualenv /venv --python=/usr/bin/python3.10 && \
    pip install --no-cache -r piptools_requirements.txt && \
    pip install --no-cache -r requirements.txt

COPY .jshintrc Gruntfile.js /srv/confidant/
COPY confidant/public /srv/confidant/confidant/public

RUN node_modules/grunt-cli/bin/grunt build --force

COPY . /srv/confidant

EXPOSE 80

CMD ["gunicorn", "confidant.wsgi:app", "--workers=2", "-k", "gevent", "--access-logfile=-", "--error-logfile=-"]
