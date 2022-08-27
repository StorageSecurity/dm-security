#!/bin/sh

docker run  --rm influxdb influxd print-config > influxdb_config.yaml || exit 1

mkdir -p $PWD/influxdb-data || exit 1

docker run --rm -d \
	--network=host \
	-v $PWD/influxdb_config.yaml:/etc/influxdb2/config.yml \
	-v $PWD/influxdb-data:/var/lib/influxdb2 \
	--name influxdb \
	influxdb


