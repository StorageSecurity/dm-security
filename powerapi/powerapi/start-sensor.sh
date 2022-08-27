#!/bin/sh

docker run -itd --rm --net=host \
       --privileged --pid=host \
       --name rapl_sensor \
       -v /sys:/sys \
       -v /var/lib/docker/containers:/var/lib/docker/containers:ro \
       -v /tmp/powerapi-sensor-reporting:/reporting \
       -v $(pwd):/srv \
       -v $(pwd)/configs/sensor_config.json:/config_file.json \
       powerapi/hwpc-sensor --config-file /config_file.json
