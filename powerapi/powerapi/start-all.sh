#!/bin/sh

./start-mongodb.sh || exit 1
echo "MongoDB started"
sleep 5

./start-sensor.sh || exit 1
echo "HWPC senor started"
sleep 5

./start-rapl.sh || exit 1
echo "RAPL (Running Average Power Limit) started"

