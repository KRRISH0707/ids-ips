# Production checklist

## Security
- [ ] OIDC/SSO and MFA
- [ ] RBAC enforced server-side
- [ ] Secrets stored in a secrets manager
- [ ] TLS everywhere
- [ ] Network segmentation
- [ ] Least-privilege service accounts
- [ ] Dependency/container scanning
- [ ] SBOM generation
- [ ] Signed container images

## Reliability
- [ ] Multiple sensors
- [ ] Local sensor buffering
- [ ] Kafka replication
- [ ] PostgreSQL HA/backups
- [ ] OpenSearch cluster
- [ ] Disaster recovery procedure
- [ ] Tested restore
- [ ] Monitoring and alerting

## Detection
- [ ] Version-controlled rules
- [ ] Rule unit tests
- [ ] Replay test dataset
- [ ] False-positive measurement
- [ ] Asset criticality
- [ ] Threat-intelligence enrichment
- [ ] Correlation
- [ ] Explainable risk score

## IPS
- [ ] Dry-run mode
- [ ] Analyst approval
- [ ] Allowlists
- [ ] Time-limited blocks
- [ ] Automatic expiry
- [ ] Rollback
- [ ] Emergency disable
- [ ] Full audit trail

## Operations
- [ ] CI/CD
- [ ] Infrastructure as code
- [ ] Central logging
- [ ] Metrics
- [ ] On-call runbook
- [ ] Incident response runbook
- [ ] Capacity planning
