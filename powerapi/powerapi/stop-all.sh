#!/bin/sh

./stop-rapl.sh || exit 1
echo "RAPL (Running Average Power Limit) stopped"

./stop-sensor.sh || exit 1
echo "HWPC senor stoped"

./stop-mongodb.sh || exit 1
echo "MongoDB stopped"

