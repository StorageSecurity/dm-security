#!/bin/sh

docker run -d \
       --name mongo_rapl \
       -p 27017:27017 \
       mongo
