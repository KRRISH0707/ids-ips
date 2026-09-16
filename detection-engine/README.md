# Detection engine

Responsibilities:
1. Normalize Suricata/Zeek events.
2. Enrich with asset inventory and threat intelligence.
3. Execute deterministic rules.
4. Correlate related events.
5. Calculate explainable risk scores.
6. Emit alerts/incidents to Kafka and persistence layers.

Keep detections version-controlled and test them with replayed datasets before production rollout.
