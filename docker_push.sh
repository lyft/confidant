#!/bin/bash
want_push='false'
for branch in "master" "1.0" "1.1"
do
   if [ "$TRAVIS_BRANCH" == "$branch" ]
   then
       want_push='true'
   fi
done
if [ "$TRAVIS_PULL_REQUEST" == "false" -a "$want_push" == "true" ]
then
    docker login -e $DOCKER_EMAIL -u $DOCKER_USERNAME -p $DOCKER_PASSWORD
    export TAG=`if [ "$TRAVIS_BRANCH" == "master" ]; then echo "latest"; else echo $TRAVIS_BRANCH ; fi`
    echo "TAG is $TAG"
    docker tag $TRAVIS_REPO_SLUG:$TRAVIS_COMMIT $REPO:$TRAVIS_TAG
    docker push $TRAVIS_REPO_SLUG:$TRAVIS_TAG
else
    echo 'Ignoring PR branch for docker push.'
fi
