# Suricata sensor

Place your authorized lab/production Suricata configuration here.

The production deployment should normally use:
- a dedicated sensor host
- a SPAN port or network TAP
- tuned AF_PACKET/DPDK depending on throughput
- persistent local event buffering
- EVE JSON output
- rule update/validation process
- sensor health monitoring

Do not run an IPS inline until the detection policy has been tested and an emergency bypass procedure exists.
