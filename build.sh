#!/bin/bash
# access_token = 5b5efa54-6113-48e2-9053-79ce9b3b04f4
NAME_SPACE="socialalphaoip"
IMAGE_NAME="auth-microservice"
TAG="prod"
docker login --username tejpochiraju --password 5b5efa54-6113-48e2-9053-79ce9b3b04f4
docker build -t $NAME_SPACE/$IMAGE_NAME:$TAG .
docker push $NAME_SPACE/$IMAGE_NAME:$TAG
