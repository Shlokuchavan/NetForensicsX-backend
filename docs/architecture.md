# NetForensicX Architecture

## Phase 0/1

The first vertical slice is intentionally small:

```text
Next.js UI
    |
    | REST
    v
FastAPI
    |
    | SQLAlchemy async
    v
PostgreSQL
```

Evidence processing is not connected yet.

## Planned Phase 2+

```text
PCAP
  |
  v
Evidence service
  |
  +--> SHA-256
  +--> capinfos validation
  +--> metadata
  |
  v
Analysis job
  |
  +--> TShark
  +--> Zeek
  |
  v
Normalized forensic records
  |
  +--> Hosts
  +--> Flows
  +--> DNS
  +--> HTTP
  +--> TLS
  |
  v
Detection engine
  |
  +--> Port scan
  +--> Host scan
  +--> Beacon
  +--> DNS anomaly
  +--> Data transfer
  |
  v
Correlation
  |
  +--> IOC
  +--> Timeline
  +--> Graph
  +--> ATT&CK mapping
  |
  v
Investigation workspace
  |
  v
Report
