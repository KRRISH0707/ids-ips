# Zeek sensor

Deploy Zeek on a dedicated authorized monitoring interface.

Recommended production approach:
- ship Zeek logs as structured JSON/TSV
- include a stable sensor ID
- buffer during central-platform outages
- monitor capture loss
- version and test scripts before rollout
