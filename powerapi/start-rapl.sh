#!/bin/sh

docker run -t --net=host \
       -v $(pwd)/rapl_config.json:/config_file.json \
       powerapi/rapl-formula --config-file /config_file.json
