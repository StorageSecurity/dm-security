#!/bin/sh

./rapl-auto-config.sh || exit 1

docker run -itd \
       --net=host \
       -v $(pwd)/configs/rapl_config.json:/config_file.json \
       --name rapl_formula \
       powerapi/rapl-formula --config-file /config_file.json

