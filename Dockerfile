FROM ubuntu:trusty
MAINTAINER Ryan Lane <rlane@lyft.com>

RUN apt-get update && \
    # For frontend
    apt-get install -y ruby-full npm nodejs nodejs-legacy git git-core && \
    # For backend
    apt-get install -y python python-pip python-dev build-essential libffi-dev \
                       libxml2-dev libxmlsec1-dev

COPY ./requirements.txt /srv/confidant/requirements.txt
COPY ./package.json /srv/confidant/package.json
COPY ./bower.json /srv/confidant/bower.json

WORKDIR /srv/confidant

RUN pip install -U pip && pip install -r requirements.txt

RUN gem install compass && \
    npm install grunt-cli && \
    npm install

COPY . /srv/confidant

RUN node_modules/grunt-cli/bin/grunt build

EXPOSE 80

CMD ["gunicorn","wsgi:app","--workers=2","-k","gevent","--access-logfile=-","--error-logfile=-"]
