# NetForensicX

Modern network-forensics investigation platform foundation.

## Phase 0/1

Included:

- Docker Compose
- PostgreSQL 17
- FastAPI + SQLAlchemy 2 async
- Next.js App Router + TypeScript
- Tailwind CSS v4
- shadcn/ui-style local components
- Case management API
- Initial modern DFIR/SOC dashboard
- Health checks
- Persistent PostgreSQL volume
- Evidence directory structure

## Architecture

Browser
  -> Next.js :3000
  -> FastAPI :8000
  -> PostgreSQL :5432

The application is intentionally ready for the next phase:

PCAP upload -> evidence hashing -> analysis workers -> TShark/Zeek -> normalized forensic data.

## Requirements

- Docker Desktop
- Docker Compose v2

For local non-Docker frontend development, Node.js 20.9+ is required by current Next.js documentation.

## Start

```bash
cd NetForensicX
docker compose up --build
```

Open:

- Frontend: http://localhost:3000
- API: http://localhost:8000
- Swagger: http://localhost:8000/docs
- Health: http://localhost:8000/health

## Stop

```bash
docker compose down
```

To also remove the database volume:

```bash
docker compose down -v
```

## Project layout

```text
NetForensicX/
├── backend/
├── frontend/
├── evidence/
├── docs/
├── docker-compose.yml
└── .env.example
```

## API

Current endpoints:

```text
GET  /health
GET  /api/v1/cases
POST /api/v1/cases
GET  /api/v1/cases/{case_id}
```

## Next implementation

Phase 2 will add:

1. Evidence upload
2. SHA-256 integrity hash
3. PCAP validation
4. Evidence metadata
5. Background analysis jobs
