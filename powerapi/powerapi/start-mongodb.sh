#!/bin/sh

DATA=$(pwd)/mongo-data

mkdir -p $DATA || exit 1

docker run -d \
       --net=host \
       -v $DATA:/data/db \
       --name mongo_rapl \
       mongo || exit 1

