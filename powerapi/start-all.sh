#!/bin/sh

./start-mongodb.sh || exit 1
echo "MongoDB started"

./start-sensor.sh || exit 1
echo "HWPC senor started"

./start-rapl.sh || exit 1
echo "RAPL (Running Average Power Limit) started"

