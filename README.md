# Enterprise IDS/IPS Platform — Production-Oriented Starter

This repository is a production-oriented foundation for a distributed IDS/IPS platform.

## Stack
- Suricata: network IDS/IPS sensor
- Zeek: network telemetry
- Kafka: event streaming
- OpenSearch: high-volume event search
- PostgreSQL: transactional/control-plane data
- Redis: cache/state
- FastAPI: backend API
- React + Vite: SOC dashboard
- Nginx: frontend reverse proxy
- Prometheus/Grafana: observability

## Important
This is a secure development/lab starter, not a turnkey production deployment. Run sensors and IPS enforcement only on networks you own or are explicitly authorized to test.

## Quick start

1. Install Docker Desktop with WSL2 on Windows, or Docker Engine + Compose on Linux.
2. Copy `.env.example` to `.env`.
3. Start the control-plane services:

```bash
docker compose up -d postgres redis kafka opensearch backend frontend
```

4. Open:
- SOC UI: http://localhost:3000
- API docs: http://localhost:8000/docs
- OpenSearch: http://localhost:9200

The network sensor profiles are intentionally separate because Suricata/Zeek need host networking, packet access, and additional privileges that should be reviewed before enabling them.

## Roadmap
1. Sensor ingestion
2. Kafka event pipeline
3. Detection/correlation
4. Alert and incident management
5. Threat intelligence
6. Analyst-approved IPS actions
7. Automated response policies with safeguards
8. HA deployment
9. Kubernetes
10. CI/CD, image signing, SBOM and security scanning
