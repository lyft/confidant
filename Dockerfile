FROM ubuntu:bionic
LABEL maintainer="rlane@lyft.com"

WORKDIR /srv/confidant

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && /usr/bin/curl -sL --fail https://deb.nodesource.com/setup_8.x | bash -
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        # For frontend
        make nodejs git-core \
        # For backend
        gcc pkg-config \
        python3-dev virtualenv \
        libffi-dev libxml2-dev libxmlsec1-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY package.json

RUN npm install grunt-cli && \
    npm install

COPY piptools_requirements*.txt requirements*.txt

ENV PATH=/venv/bin:$PATH
RUN virtualenv /venv -ppython3 && \
    pip install --no-cache -r piptools_requirements3.txt && \
    pip install --no-cache -r requirements3.txt

COPY confidant/public /srv/confidant/confidant/public

RUN node_modules/grunt-cli/bin/grunt build

COPY . /srv/confidant

EXPOSE 80

CMD ["gunicorn", "confidant.wsgi:app", "--workers=2", "-k", "gevent", "--access-logfile=-", "--error-logfile=-"]
