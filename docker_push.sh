#!/bin/bash
if [ "$TRAVIS_PULL_REQUEST" == "false" -a -n "$TRAVIS_TAG" ]
then
    docker login -u $DOCKER_USERNAME -p $DOCKER_PASSWORD
    export TAG="$TRAVIS_TAG"
    echo "TAG is $TAG"
    docker tag $TRAVIS_REPO_SLUG:$TRAVIS_COMMIT $REPO:$TAG
    docker push $TRAVIS_REPO_SLUG:$TAG
elif [ "$TRAVIS_PULL_REQUEST" == "false" -a "$TRAVIS_BRANCH" == "master" ]
then
    docker login -u $DOCKER_USERNAME -p $DOCKER_PASSWORD
    export TAG="latest"
    echo "TAG is $TAG"
    docker tag $TRAVIS_REPO_SLUG:$TRAVIS_COMMIT $REPO:$TAG
    docker push $TRAVIS_REPO_SLUG:$TAG
else
    echo 'Ignoring PR branch for docker push.'
fi
