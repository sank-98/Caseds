# CASEDS

CASEDS is a modular threat-detection system for suspicious messages and links. It normalizes incoming content, extracts risk features, runs NLP + pattern intelligence, and returns an explainable threat score.

## Project Overview

Pipeline stages:
1. **Input normalization** (`caseds/pipeline/input_layer.py`)
2. **Feature extraction** (`caseds/pipeline/feature_extraction/*`)
3. **Intelligence** (`caseds/pipeline/intelligence/*`)
4. **Risk scoring + API response** (`main.py`, `scoring.py`)

## Installation & Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Run locally:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## API Endpoints

### `GET /health`
Returns system health and module status.

### `POST /analyze`
Analyzes a suspicious input payload.

Example request:

```json
{
  "input_type": "email",
  "subject": "Urgent: Verify your account now",
  "body": "Your account is suspended. Verify immediately at http://bit.ly/alert-login",
  "sender": "Security Team <alerts@paypa1.com>",
  "urls": ["http://bit.ly/alert-login"],
  "email_headers": {
    "spf_result": "fail",
    "dkim_result": "fail",
    "dmarc_result": "fail"
  },
  "user_id": "user-123"
}
```

Example response fields:
- `threat_score` (0-100)
- `risk_level` (`safe`, `suspicious`, `high_risk`)
- `classification` (`phishing`, `impersonation`, `scam`, `benign`)
- `score_breakdown` by component
- `triggered_indicators` and `pattern_matches`

## Configuration Reference

Environment variables (`.env.example`):
- `DEBUG`
- `API_HOST`
- `API_PORT`
- `LOG_LEVEL`
- `USE_TRANSFORMER`
- `VIRUSTOTAL_API_KEY`
- `DATABASE_URL`

## Testing

Run focused tests:

```bash
pytest caseds/tests -q
```

## Deployment

### Docker

```bash
docker build -t caseds .
docker run --rm -p 8000:8000 caseds
```

Or with compose:

```bash
docker compose up --build
```

### GitHub Pages

A workflow is provided at `.github/workflows/deploy.yml`.

1. In repository settings, enable **Pages** and set source to **GitHub Actions**.
2. Push to `main`.
3. The workflow deploys `docs/index.html` to Pages.

## Usage Notes

- Transformer-based classification is optional (`USE_TRANSFORMER=true`).
- Default mode uses deterministic heuristics for lightweight deployments and tests.
