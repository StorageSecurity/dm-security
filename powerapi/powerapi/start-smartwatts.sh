#!/bin/sh

./smartwatts-auto-config.sh || exit 1

docker run -t --rm \
	--net=host \
	--name smartwatts \
	-v $(pwd)/configs/smartwatts_config.json:/config_file.json \
	powerapi/smartwatts-formula --config-file /config_file.json

