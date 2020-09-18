# IoT-Fingerprint
Methods to Fingerprint Internet Connected Devices for Identity Profiling

## Fingerprint Manufuctuer

This method uses OUI data to get the Manufacturer or Vendor ID

'OUI=$(ip addr list|grep -w 'link'|awk '{print $2}'|grep -P '^(?!00:00:00)'| grep -P '^(?!fe80)' | tr -d ':' | head -c 6)'

where 'ip addr' is the input.

example output 
