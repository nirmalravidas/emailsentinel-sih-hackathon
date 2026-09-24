# EmailSentinel

**AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform**

> **Prototype for demonstration and research.** Not a production security product. IP geolocation shows
> where network *infrastructure* is located, not the attacker's physical location or identity, and the risk
> score is a heuristic, not a scientifically validated probability.

---

## 1. What EmailSentinel does

Send it a raw email (an `.eml` file or pasted text) and one API call returns a structured forensic report:

- NLP classification of the message (legitimate / phishing / fraud) with the words that drove the decision
- Sender identity checks (Display Name vs From vs Reply-To vs Return-Path)
- URL indicators (URLs are only parsed, **never opened**)
- Received-header relay chain and a labelled `probable_origin_ip`
- IP geolocation, DNS records, SPF / DKIM / DMARC results read from headers
- Lookalike (typosquatted) domain detection against a small brand list
- An explainable 0-100 risk score with the reason for every point
- Indicators of compromise (IPs, domains, URLs, attachment hashes) and a stored case history

## 2. Architecture

Single FastAPI service, no frontend, no auth.

```
POST /api/v1/analyze-email  (.eml upload OR raw text)
        |
   email_parser        -> headers, body, URLs, attachments, MIME
        |
   nlp_service         -> TF-IDF + Logistic Regression  (+ separate rule-based heuristics)
   header_analyzer     -> identity mismatch, Received chain, SPF/DKIM/DMARC
   url_analyzer        -> per-URL risk indicators
   domain_analyzer     -> lookalike detection (edit distance)
   ip_intelligence     -> ip-api.com geolocation (public IPs only)
   dns_service         -> A / MX / TXT via dnspython (+ optional WHOIS)
        |
   risk_engine         -> explainable additive score, level, reasons
        |
   SQLite (cases)  +  one JSON response
```

```
emailsentinel/
├── app/
│   ├── main.py                 FastAPI app, /health, model + DB startup
│   ├── config.py               settings / env vars
│   ├── api/routes.py           endpoints + pipeline orchestration
│   ├── services/               one module per analysis stage (see diagram)
│   ├── models/schemas.py       Pydantic models (drive Swagger docs)
│   └── database/database.py    SQLite case storage
├── data/email_dataset.csv      demo training set (text,label)
├── models/email_nlp_model.joblib   trained model (auto-trained if missing)
├── samples/                    phishing_email.eml, legitimate_email.eml
├── requirements.txt  README.md  .env.example
```

## 3. How NLP is used

`app/services/nlp_service.py` has two independent parts:

1. **ML classifier.** `subject + body` is cleaned (lowercase, URLs/emails replaced by placeholder tokens,
   punctuation and numbers removed), vectorised with `TfidfVectorizer` (1-2 grams, stop words removed) and
   classified by `LogisticRegression` into `legitimate`, `phishing` or `fraud`. The output is the class,
   its probability (`confidence`), all class probabilities, and `keywords` - the words in *this* email that
   pushed the model most strongly toward the predicted class.
2. **Heuristics.** Regex rules flag urgency, financial request, credential request, account-suspension
   threat, impersonation language and suspicious call-to-action, and report the matched phrases as evidence.

The model output and the heuristic output are kept in separate fields.

The training set (`data/email_dataset.csv`, ~100 short hand-written examples) is only for demonstration.
5-fold cross-validation on it gave about 0.90 accuracy, but that number mostly shows the demo data is easy;
do not treat it as real-world performance. To retrain after editing the CSV:

```bash
python -m app.services.nlp_service
```

## 4. How email headers are analyzed

- **Identity:** display name, From, Reply-To and Return-Path are compared by registrable domain. Flags:
  Reply-To differs from sender, Return-Path differs (noted as often normal for bulk mail), display name
  naming a known brand while the domain is not that brand's, or an email address in the display name that
  belongs to another domain.
- **Received chain:** every `Received:` header is parsed (from-host, IP, by-host, protocol, timestamp). Headers
  are added newest-first, so the chain is reversed and returned **oldest first**.
  `probable_origin_ip` is the earliest *public* IP in the chain (falls back to the earliest IP, then
  `X-Originating-IP`). Received headers can be forged, so this is a lead, not proof.
- **Authentication:** SPF, DKIM and DMARC results are read from `Authentication-Results` (and `Received-SPF`
  for SPF). If absent they are `"unknown"`. **No cryptographic DKIM verification is performed.**
- **Lookalike domains:** Levenshtein similarity after undoing character substitutions (`0->o`, `1->l/i`,
  `rn->m`, `vv->w`), plus checks for the brand embedded in a longer domain (`micros0ft-security.com`), the
  same name on another TLD, and `microsoft.com.evil.net`. Compared against `KNOWN_BRANDS` in
  `domain_analyzer.py`. This is a heuristic indicator, not proof of impersonation.

## 5. How IP geolocation works

Public IPs from the Received chain are looked up on the free `ip-api.com` endpoint (country, region, city,
ISP, organization, ASN). Private, loopback and reserved addresses are **never** sent to the service and
return `{"status": "private_ip", "message": "Geolocation unavailable for private IP"}`. If the service is
unreachable or rate-limited (the free tier allows about 45 requests/minute and is HTTP only), the response
says `lookup_failed` and the rest of the analysis still works. The result describes network infrastructure
(often a VPN, hosting provider or compromised server), not the sender's physical location or identity.

## 6. How risk scoring works

`risk_engine.py` adds up fixed, documented points (maximum 100). Nothing is hidden: the response includes
`reasons` and a `score_breakdown`.

| Group | Max | Details |
|---|---|---|
| NLP model | 30 | 30 x (1 - P(legitimate)) |
| NLP heuristics | 15 | urgency 4, credential 4, financial 3, suspension 2, impersonation 1, CTA 1 |
| URLs | 15 | HTTP 3, suspicious keywords 6, IP / obfuscation / shortener / risky TLD 6 |
| Identity | 15 | Reply-To mismatch 7, brand in display name 5, Return-Path mismatch 3 |
| Authentication | 15 | SPF fail 6 (softfail 3), DKIM fail 4, DMARC fail 5 |
| Lookalike domain | 10 | any lookalike match |

Levels: 0-29 Low, 30-59 Medium, 60-79 High, 80-100 Critical. DNS data is **not** part of the score. If the
NLP model says `legitimate` but the rules push the score to High/Critical, the classification becomes
`suspicious`. The weights are hand-picked for the demo.

## 7. Installation

Python 3.11+.

```bash
cd emailsentinel
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m app.services.nlp_service   # trains models/email_nlp_model.joblib (also auto-runs on first start)
cp .env.example .env                 # optional
```

## 8. Running the server

```bash
uvicorn app.main:app --reload
```

Swagger UI: <http://127.0.0.1:8000/docs> (OpenAPI JSON at `/openapi.json`).

## 9. Swagger usage (demo flow)

1. Open `/docs`, expand **POST /api/v1/analyze-email**, click **Try it out**.
2. Under `file`, choose `samples/phishing_email.eml` (or paste the whole raw email into `raw_email`). Execute.
3. Read the JSON: `threat_assessment`, `nlp_analysis`, `identity_analysis`, `authentication`, `url_analysis`,
   `relay_analysis`, `geolocation`, `domain_intelligence`, `indicators_of_compromise`.
4. Run it again with `samples/legitimate_email.eml` to compare (score about 4, Low).
5. Try **POST /api/v1/nlp/analyze** with `{"text": "Your account will be suspended. Verify immediately."}`
   and **GET /api/v1/cases** for the stored history.

Same thing from the command line:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze-email -F "file=@samples/phishing_email.eml"
curl -X POST http://127.0.0.1:8000/api/v1/analyze-email -F "raw_email=<samples/phishing_email.eml"
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/v1/cases
```

The sample phishing email is fictional. Its origin IP `8.8.8.8` is only a placeholder public address so
geolocation can be demonstrated; it does not mean Google sent it.

## 10. Example API response

Abridged output for `samples/phishing_email.eml` (real values from a test run; the `geolocation` block is
shown as returned when `ip-api.com` is reachable):

```json
{
  "analysis_id": "8f570e59-c036-4ed4-99be-0e6058081e99",
  "email_summary": {
    "subject": "Urgent: Verify Your Account",
    "from": "Microsoft Support <support@micros0ft-security.com>",
    "reply_to": "attacker@example.com",
    "return_path": "<bounce@relay-node7.example.net>"
  },
  "threat_assessment": {
    "classification": "phishing",
    "risk_score": 87,
    "risk_level": "Critical",
    "reasons": [
      "NLP model detected phishing language (threat probability 0.99)",
      "Urgent / time-pressure language detected",
      "Request for credentials or personal verification detected",
      "Account suspension / lock threat detected",
      "Impersonation-style wording (e.g. 'Security Team') detected",
      "Suspicious call-to-action (e.g. 'click here') detected",
      "..."
    ]
  },
  "nlp_analysis": {
    "confidence": 0.991,
    "keywords": [
      "verify",
      "account",
      "click",
      "password",
      "immediately",
      "suspended"
    ],
    "social_engineering_indicators": [
      "urgency",
      "credential request",
      "account suspension threat",
      "impersonation language",
      "suspicious call-to-action"
    ]
  },
  "identity_analysis": {
    "identity_mismatch": true,
    "lookalike_domain": true,
    "matched_brand": "Microsoft"
  },
  "authentication": {
    "spf": "fail",
    "dkim": "none",
    "dmarc": "fail"
  },
  "url_analysis": [
    {
      "url": "http://example-login-security.com/verify",
      "domain": "example-login-security.com",
      "risk_indicators": [
        "HTTP (no TLS)",
        "login keyword",
        "verify keyword",
        "security keyword"
      ]
    }
  ],
  "relay_analysis": {
    "probable_origin_ip": "8.8.8.8",
    "relay_chain": [
      "... 4 hops, oldest first ..."
    ]
  },
  "geolocation": {
    "probable_origin_ip": {
      "ip": "8.8.8.8",
      "status": "ok",
      "country": "United States",
      "region": "California",
      "city": "Mountain View",
      "isp": "Google LLC",
      "organization": "Google Public DNS",
      "asn": "AS15169 Google LLC"
    },
    "disclaimer": "..."
  },
  "domain_intelligence": {
    "domains": [
      "... A / MX / TXT per sender + URL domain ..."
    ]
  },
  "indicators_of_compromise": {
    "ips": [
      "8.8.8.8"
    ],
    "domains": [
      "micros0ft-security.com",
      "example.com",
      "relay-node7.example.net",
      "example-login-security.com"
    ],
    "urls": [
      "http://example-login-security.com/verify"
    ],
    "attachment_sha256": []
  },
  "explanation": [
    "Phishing-like language detected",
    "Social-engineering language detected",
    "Suspicious URL detected",
    "Sender identity mismatch detected",
    "Email authentication failed",
    "Suspicious domain detected"
  ]
}
```

## 11. Postman demo

Start the service with `uvicorn app.main:app --reload`, then create these requests in Postman:

1. `GET http://127.0.0.1:8000/health` - confirm the service is running.
2. `POST http://127.0.0.1:8000/api/v1/analyze-email` - choose **Body > form-data**, add a key named
  `file`, change its type from **Text** to **File**, and select any `.eml` file from `samples/`.
3. `POST http://127.0.0.1:8000/api/v1/nlp/analyze` - choose **Body > raw > JSON** and send
  `{ "text": "Your account will be suspended. Verify immediately." }`.
4. `GET http://127.0.0.1:8000/api/v1/cases` - show the stored analysis history.

The five additional upload-ready examples are `01_legitimate_project_update.eml`,
`02_account_verification_phishing.eml`, `03_invoice_payment_fraud.eml`, `04_suspicious_attachment.eml`,
and `05_html_link_scam.eml`. The API returns one structured JSON report per upload; compare
`threat_assessment.classification`, `threat_assessment.risk_score`, `url_analysis`, and
`indicators_of_compromise` during the demo.

## 12. Limitations

- Prototype only: tiny demo dataset (~100 rows), so the classifier will make mistakes on real-world email.
- Risk weights are hand-set; the score is not a calibrated probability.
- Headers such as `Received` and `Authentication-Results` can be forged; results are only as trustworthy as the
  receiving mail server that added them. No cryptographic DKIM verification, no live SPF/DMARC evaluation.
- Geolocation is infrastructure location from a free third-party service (rate limited, HTTP only, can be
  wrong). It never identifies an attacker.
- Lookalike detection uses a six-brand list and simple string similarity; expect false positives and misses.
- URLs are never fetched or sandboxed, so redirects and page content are not analysed.
- Handles common `.eml` structures only; heavily malformed or exotic messages may be partially parsed.
- No authentication, rate limiting or encryption; do not expose it to the internet as is. Only case metadata
  is stored in SQLite, never full email content.
- DNS lookups and geolocation send the sender's domains/IPs to your DNS resolver and ip-api.com. Set
  `ENABLE_DNS=false` / `ENABLE_GEOLOCATION=false` in `.env` for fully offline analysis.
