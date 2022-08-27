#!/bin/sh

echo "
{
  \"verbose\": true,
  \"stream\": true,
  \"input\": {
    \"puller\": {
      \"model\": \"HWPCReport\",
      \"type\": \"mongodb\",
      \"uri\": \"mongodb://127.0.0.1\",
      \"db\": \"db_sensor\",
      \"collection\": \"report_0\"
    }
  },
  \"output\": {
    \"pusher_power\": {
      \"type\": \"mongodb\",
      \"model\": \"PowerReport\",
      \"uri\": \"mongodb://127.0.0.1\",
      \"db\": \"db_rapl\",
      \"collection\": \"results\"
    }
  },
  \"enable-dram-formula\": true,
  \"sensor-report-sampling-interval\": 500
}
" > ./configs/rapl_config.json
