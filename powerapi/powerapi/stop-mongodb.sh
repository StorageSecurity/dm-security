#!/bin/sh

docker stop mongo_rapl || exit 1
docker rm mongo_rapl || exit 1


