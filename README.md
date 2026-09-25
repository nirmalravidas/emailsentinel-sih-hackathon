# EmailSentinel

EmailSentinel is an AI-assisted email threat detection and forensic intelligence platform. It accepts raw
`.eml` evidence, analyzes content and technical headers, reconstructs the visible relay path, identifies
indicators of compromise, estimates infrastructure geolocation, correlates optional external threat
intelligence, and presents the result through a FastAPI API and browser dashboard.

> **MVP status:** suitable for demonstration, academic work, and controlled internal evaluation. It is not
a production security product. Risk scores and attribution signals are heuristic and must be reviewed by
a qualified analyst.

## What It Provides

- `.eml` upload or pasted raw email analysis
- TF-IDF and Logistic Regression classification for legitimate, phishing, and fraud-like messages
- Rule-based detection for urgency, credential theft, payment requests, account suspension, impersonation,
  and suspicious calls to action
- Sender identity comparison across Display Name, From, Reply-To, and Return-Path
- Lookalike and typosquatted-domain detection
- URL parsing without opening or fetching URLs
- Detection of HTTP links, suspicious keywords, IP-based links, shorteners, risky TLDs, redirects, and
  common URL obfuscation
- Attachment metadata and SHA-256 hashes
- Received-header parsing and oldest-first relay reconstruction
- Probable origin IP selection from public Received-header addresses or `X-Originating-IP`
- IP infrastructure geolocation: country, region, city, ISP, organization, and ASN
- Receiver-reported SPF, DKIM, and DMARC results
- Independent SPF DNS evaluation, DKIM cryptographic verification, and DMARC policy/alignment checks
- Explainable 0-100 risk score with reason and score breakdown
- Optional AbuseIPDB, URLhaus, ThreatFox, Tor exit-list, and DNSBL correlation
- PostgreSQL-ready persistence with SQLite fallback for local development
- Redis caching and optional Celery asynchronous analysis
- Case history, workflow status, analyst notes, timelines, IOCs, correlations, and campaigns
- High-risk database alerts
- PDF forensic report export
- Browser dashboard served directly by FastAPI
- Interactive Leaflet infrastructure map and relay-path graph in the Network report tab
- Configurable sensitive-field masking and retention cleanup

## Architecture

EmailSentinel is a modular monolith with an optional asynchronous worker:

```text
Browser dashboard / API client
              |
              v
        FastAPI application
              |
              v
     Shared forensic pipeline
              |
   +----------+-----------+------------------+
   |          |           |                  |
 Parser     NLP       Header/auth        URL/domain
   |          |           |                  |
   +----------+-----------+------------------+
              |
   +----------+-----------+------------------+
   |          |           |                  |
 Geolocation DNS     Threat intelligence  Risk engine
              |
              v
     JSON report and persisted case
              |
   PostgreSQL / SQLite, Redis, Celery
```

### Runtime modes

**Local mode** uses the project virtual environment and SQLite. Redis is optional and external lookups fail
gracefully. This is the fastest mode for development.

**Docker mode** runs PostgreSQL, Redis, an Alembic migration job, the FastAPI API, and a Celery worker.
This is the preferred mode for testing the complete service topology.

## Repository Layout

```text
emailsentinel/
├── app/
│   ├── main.py                         FastAPI bootstrap and frontend serving
│   ├── config.py                       Environment-backed configuration
│   ├── api/routes.py                    Analysis, cases, campaigns, alerts, reports
│   ├── models/schemas.py                Pydantic request and response schemas
│   ├── database/database.py             SQLAlchemy repository functions
│   ├── database/models/entities.py      PostgreSQL-ready ORM entities
│   ├── services/
│   │   ├── analysis_service.py          Shared synchronous/Celery pipeline
│   │   ├── email_parser.py              MIME, headers, body, URLs, attachments
│   │   ├── nlp_service.py               ML classifier and heuristics
│   │   ├── header_analyzer.py            Identity, relay, SPF/DKIM/DMARC
│   │   ├── threat_intel_service.py       External reputation and infrastructure checks
│   │   ├── ip_intelligence.py             Infrastructure geolocation
│   │   ├── dns_service.py                A, MX, TXT, and optional WHOIS
│   │   ├── risk_engine.py                 Explainable risk scoring
│   │   ├── privacy_service.py             Optional sensitive-field masking
│   │   └── report_service.py              PDF report generation
│   └── workers/                          Celery application and tasks
├── frontend/                             Dashboard HTML, CSS, and JavaScript
├── alembic/                              Database migrations
├── data/email_dataset.csv                Demonstration training data
├── models/email_nlp_model.joblib         Saved demonstration model
├── samples/                              Example `.eml` evidence
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example                          Public key-only configuration template
└── README.md
```

## Requirements

For local development:

- Python 3.11 or newer
- Optional Node.js for `node --check frontend/app.js`
- Network access if DNS, geolocation, SPF, DMARC, DKIM, or threat-intelligence checks are enabled

For Docker:

- Docker Engine or Docker Desktop
- Docker Compose v2
- Permission to access the Docker daemon socket on Linux

## Local Installation

```bash
cd /home/nirmalravidas/codeplay/projects/emailsentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The repository includes a demonstration model. If it is missing or needs retraining:

```bash
python -m app.services.nlp_service
```

The public `.env.example` file intentionally contains keys without values. Create a private `.env` only
when you need to override defaults:

```bash
cp .env.example .env
```

The real `.env` is ignored by Git. Never commit passwords, API keys, tokens, private keys, or certificates.

## Run Locally

```bash
source .venv/bin/activate
uvicorn app.main:app --reload
```

Open the dashboard:

```text
http://127.0.0.1:8000/
```

Open API documentation:

```text
http://127.0.0.1:8000/docs
```

Check service health:

```bash
curl http://127.0.0.1:8000/health
```

Use the dashboard to upload one of the files in `samples/`, or call the API directly:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze-email \
  -F "file=@samples/phishing_email.eml"
```

Raw text can also be submitted:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze-email \
  -F "raw_email=<samples/phishing_email.eml"
```

## Run with Docker

On Linux, if Docker reports permission denied for `/var/run/docker.sock`, add your user to the Docker
group and start a new shell:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
```

Create a private environment file and set the required database password:

```bash
cp .env.example .env
sed -i 's/^POSTGRES_PASSWORD=$/POSTGRES_PASSWORD=choose-a-local-password/' .env
```

Start the complete stack:

```bash
docker compose up --build
```

The services are:

| Service | Purpose |
|---|---|
| `postgres` | Persistent PostgreSQL database |
| `redis` | Celery broker, result backend, and cache |
| `migrate` | One-shot Alembic migration job |
| `api` | FastAPI server and dashboard |
| `worker` | Celery asynchronous analysis worker |

Verify the stack:

```bash
docker compose ps
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/api/v1/analyze-email \
  -F "file=@samples/phishing_email.eml"
```

Stop containers without deleting volumes:

```bash
docker compose down
```

Delete database and Redis volumes only when intentionally resetting local data:

```bash
docker compose down -v
```

Do not run local Uvicorn and Docker API on port `8000` at the same time.

## Configuration

Configuration is loaded from the private `.env` file and environment variables. Blank values use safe
application defaults.

### Core settings

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | SQLite file | SQLAlchemy database URL |
| `DATABASE_PATH` | `data/emailsentinel.db` | Local SQLite path |
| `MAX_EMAIL_BYTES` | 5242880 | Maximum uploaded email size |
| `ENABLE_DNS` | `true` | Enable DNS lookups |
| `ENABLE_GEOLOCATION` | `true` | Enable IP geolocation |
| `ENABLE_WHOIS` | `false` | Enable optional WHOIS lookups |
| `HTTP_TIMEOUT` | 4 | External HTTP timeout in seconds |
| `DNS_TIMEOUT` | 2.5 | DNS timeout in seconds |

### Async processing

| Variable | Default | Purpose |
|---|---|---|
| `ASYNC_ANALYSIS_ENABLED` | `false` | Return queued responses and use Celery |
| `REDIS_ENABLED` | `true` | Enable Redis cache attempts |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `CELERY_BROKER_URL` | `REDIS_URL` | Celery broker |
| `CELERY_RESULT_BACKEND` | `REDIS_URL` | Celery result backend |
| `CELERY_TIME_LIMIT` | 300 | Hard task limit in seconds |

### Privacy and retention

| Variable | Default | Purpose |
|---|---|---|
| `MASK_SENSITIVE_FIELDS` | `false` | Mask email addresses in returned and stored reports |
| `RETENTION_ENABLED` | `false` | Enable expired-case cleanup at startup |
| `RETENTION_DAYS` | 365 | Case age threshold for cleanup |

### Threat intelligence

Threat intelligence is disabled by default. Enable it only when external provider lookups are acceptable:

```env
THREAT_INTEL_ENABLED=true
ABUSEIPDB_API_KEY=your-private-key
```

Additional settings include `TOR_EXIT_LIST_URL`, `THREAT_INTEL_TIMEOUT`, and `THREAT_INTEL_DNSBL`.

When enabled, the service performs best-effort checks for:

- Tor exit-node membership
- DNSBL listings associated with abuse or open-relay infrastructure
- AbuseIPDB IP reputation and hosting/proxy metadata when an API key is configured
- URLhaus URL and domain reputation
- ThreatFox botnet and malware IOC matches

Provider failures return `lookup_failed` or `not_configured` and do not fail the email analysis. External
feeds may be incomplete, stale, rate-limited, or unavailable. A feed match is an investigative indicator,
not proof of attribution.

## Database and Migrations

Local SQLite automatically creates tables for development. Docker/PostgreSQL uses Alembic:

```bash
alembic upgrade head
```

After changing ORM models:

```bash
alembic revision --autogenerate -m "describe the change"
alembic upgrade head
```

The schema includes cases, evidence hashes, email metadata, header analysis, authentication results, URLs,
domains, IP indicators, normalized IOCs, campaigns, tasks, alerts, audit logs, and evidence events.

Raw email content is not stored by the current ingestion path. Evidence identity is preserved through a
SHA-256 hash, file size, sanitized filename, and chain-of-custody event.

## API Reference

All application endpoints are under `/api/v1`.

### Analysis

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/analyze-email` | Analyze `.eml` upload or `raw_email` form text |
| `GET` | `/analysis/{analysis_id}` | Read queued, processing, failed, or completed status |
| `POST` | `/nlp/analyze` | Test NLP and heuristic analysis on plain text |

With `ASYNC_ANALYSIS_ENABLED=true`, upload returns `202` and includes `analysis_id`, `case_id`, and
`task_id`. Poll the analysis endpoint until its status is `COMPLETED`.

### Cases and reports

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/cases` | List stored case summaries |
| `GET` | `/cases/{case_id}` | Read case metadata and persisted report |
| `GET` | `/cases/{case_id}/timeline` | Read forensic and audit timeline |
| `GET` | `/cases/{case_id}/iocs` | Read normalized case IOCs |
| `GET` | `/cases/{case_id}/correlation` | Find shared IOCs across cases |
| `GET` | `/cases/{case_id}/report` | Download complete report as JSON |
| `GET` | `/cases/{case_id}/report.pdf` | Download complete report as PDF |
| `PATCH` | `/cases/{case_id}/status` | Update workflow status and analyst notes |

Allowed case statuses are `NEW`, `ANALYZING`, `REVIEW`, `CONFIRMED_THREAT`, `FALSE_POSITIVE`, and `CLOSED`.

### Campaigns

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/campaigns` | Create an investigation campaign |
| `GET` | `/campaigns` | List campaigns |
| `GET` | `/campaigns/{campaign_id}` | Read campaign cases and indicators |
| `POST` | `/campaigns/{campaign_id}/cases/{case_id}` | Attach a case with optional similarity score |

Campaign correlation is based on shared infrastructure and IOCs. It does not prove common attacker
identity.

### Alerts

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/alerts` | List recorded high-risk alerts |
| `GET` | `/alerts/{alert_id}` | Read one alert |

High and critical analyses create one idempotent database alert with `RECORDED` delivery status. External
email, webhook, Slack, Teams, and SIEM delivery are not included in the MVP.

## Report Structure

An analysis report includes:

```text
analysis_id
evidence
email_summary
threat_assessment
nlp_analysis
identity_analysis
authentication
url_analysis
relay_analysis
geolocation
domain_intelligence
threat_intelligence
indicators_of_compromise
explanation
warnings
```

The `authentication` object contains both receiver-reported fields (`spf`, `dkim`, `dmarc`) and
`independent_validation` with SPF, DKIM, DMARC status, DNS evidence, cryptographic verification state,
and alignment information.

The `geolocation` object describes public network infrastructure such as a mail server, hosting provider,
VPN, or relay. It does not identify an attacker's physical location.

## Risk Scoring

The risk engine is explainable and capped at 100:

| Signal group | Maximum |
|---|---:|
| NLP threat probability | 30 |
| Social-engineering heuristics | 15 |
| URL indicators | 15 |
| Sender identity mismatch | 15 |
| SPF/DKIM/DMARC failures | 15 |
| Lookalike domain | 10 |

Risk levels:

- `0-29`: Low
- `30-59`: Medium
- `60-79`: High
- `80-100`: Critical

The score is a hand-weighted triage signal, not a probability or legal conclusion.

## Testing and Validation

Run the automated tests:

```bash
source .venv/bin/activate
python -m pytest -q tests
```

Run syntax and compile checks:

```bash
python -m compileall -q app
node --check frontend/app.js
git diff --check
```

The expected core checks are:

- `/health` returns `200`
- `/` serves the dashboard
- A sample `.eml` returns `200` in synchronous mode
- Authentication includes independent SPF/DKIM/DMARC results
- A case is persisted
- PDF export begins with valid `%PDF` bytes
- Campaign creation and case assignment return `200`

## Security and Privacy Notes

- `.env`, credentials, private keys, certificates, local databases, logs, and reports are ignored by Git.
- `.env.example` is a key-only public template; it contains no real values.
- Never commit `ABUSEIPDB_API_KEY`, database passwords, Redis credentials, or tokens.
- Uploaded filenames are reduced to a basename and restricted to `.eml`.
- Upload size is bounded by `MAX_EMAIL_BYTES`.
- URLs are not opened or fetched by the parser.
- Private and reserved IPs are not sent to the geolocation provider.
- Sensitive-field masking is opt-in through `MASK_SENSITIVE_FIELDS=true`.
- Retention cleanup is opt-in through `RETENTION_ENABLED=true`.
- The MVP has no authentication or role-based access control. Do not expose it directly to the public
  internet without adding access control, rate limiting, TLS, and operational logging.

## Known Limitations

- The demonstration dataset is small and is not representative of production email traffic.
- The model is not calibrated, multilingual, or continuously monitored for drift.
- Received headers and receiver-reported authentication headers can be forged.
- Independent authentication checks depend on DNS, DKIM signing keys, network access, and message integrity.
- Geolocation is approximate infrastructure location, not attacker identity or physical location.
- VPN detection is provider-dependent; the MVP uses hosting/proxy metadata where available rather than a
  dedicated commercial VPN database.
- Tor, DNSBL, AbuseIPDB, URLhaus, and ThreatFox data can be stale or rate-limited.
- Attachments are hashed and classified by metadata; there is no malware sandbox, YARA engine, or antivirus
  scanning in the MVP.
- The map depends on public geolocation coordinates and external OpenStreetMap tiles; unavailable network
  lookups fall back to structured report data.
- Alert delivery is recorded in the database; external notification integrations are future work.
- Authentication, RBAC, tenant isolation, encryption at rest, legal holds, and full compliance workflows
  are not included.

## Responsible Use

Use EmailSentinel only on email evidence that you are authorized to inspect. Treat third-party reputation,
geolocation, authentication, and attribution results as investigative leads. Preserve original evidence and
follow your organization's privacy, retention, legal, and incident-response procedures.

## License

No license has been selected for this repository yet. Add an appropriate `LICENSE` file before publishing
the project for external reuse.
