#!/bin/sh

docker run --rm --net=host \
       --privileged --pid=host \
       -v /sys:/sys \
       -v /var/lib/docker/containers:/var/lib/docker/containers:ro \
       -v /tmp/powerapi-sensor-reporting:/reporting \
       -v $(pwd):/srv \
       -v $(pwd)/sensor_config.json:/config_file.json \
       powerapi/hwpc-sensor --config-file /config_file.json
