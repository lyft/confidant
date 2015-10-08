FROM ubuntu:trusty
MAINTAINER Ryan Lane <rlane@lyft.com>

RUN apt-get update && \
    # For frontend
    apt-get install -y ruby-full npm nodejs nodejs-legacy git git-core && \
    # For backend
    apt-get install -y python python-pip python-dev build-essential libffi-dev

ADD . /srv/confidant

WORKDIR /srv/confidant

RUN gem install compass && \
    npm install grunt-cli && \
    npm install && \
    node_modules/grunt-cli/bin/grunt build

RUN pip install -r requirements_export.txt && \
    pip install -r requirements.txt

EXPOSE 80

CMD ["gunicorn","wsgi:app","--workers=2","-k","gevent"]
