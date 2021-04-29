# VirusTotal Action and Sensor for Grace Lombardi's CSEC380 Blog

## Configuration

When ssh'd into the Vagrant box run the following two commands:

`st2 key set virus_total_api_key <Insert Api Key Here>`

`st2 key set test_ip <Insert IP to test with>`

# Actions

Action                      | Description                                                       
--------------------------- | ---------------------------------------------
VirusTotalIPInfo            | This action returns the results of the analysis of an IP

# Sensors

Sensor                      | Description                                                       
--------------------------- | ---------------------------------------------
VirusTotalPollingSensor     | This sensor polls VirusTotal for IP safety votes every 2 minutes
