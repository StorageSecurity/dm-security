#!/bin/sh

maxfrequency=$(lscpu -b -p=MAXMHZ | tail -n -1| cut -d . -f 1)
minfrequency=$(lscpu -b -p=MINMHZ | tail -n -1 | cut -d . -f 1)
basefrequency=$(lscpu | grep "型号名称" | cut -d @ -f 2 | cut -d G -f 1)
basefrequency=$(expr ${basefrequency}\*1000 | bc | cut -d . -f 1)

echo "
{
  \"verbose\": true,
  \"stream\": true,
  \"input\": {
    \"puller\": {
      \"model\": \"HWPCReport\",
      \"type\": \"socket\",
      \"uri\": \"127.0.0.1\",
      \"port\": 8080,
      \"collection\": \"test_hwpc\"
    }
  },
  \"output\": {
    \"pusher_power\": {
      \"type\": \"influxdb\",
      \"model\": \"PowerReport\",
      \"uri\": \"127.0.0.1\",
      \"port\": 8086,
      \"db\": \"test\",
      \"collection\": \"prep\"
    }
  },
  \"cpu-frequency-base\": $basefrequency,
  \"cpu-frequency-min\": $minfrequency,
  \"cpu-frequency-max\": $maxfrequency,
  \"cpu-error-threshold\": 2.0,
  \"disable-dram-formula\": true,
  \"sensor-report-sampling-interval\": 1000
}
" > ./configs/smartwatts_config.json

