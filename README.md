# SerpHarvest Email Verifier API

A self-hosted email verification API with SMTP verification. Built for SerpHarvest Pro.

## Endpoints

- `GET /health` — Health check
- `POST /api/validate-single` — Validate one email
- `POST /api/validate-bulk` — Validate up to 1000 emails
- `POST /api/find-email` — Find valid email from name + domain (MAIN ENDPOINT)

## Deploy to Railway (Free)

1. Go to https://railway.app and sign up
2. Click "New Project" → "Deploy from GitHub"
3. Upload these files to a GitHub repo first
4. Railway auto-detects Python and deploys
5. Copy your Railway URL

## Deploy to Render (Free)

1. Go to https://render.com and sign up
2. Click "New" → "Web Service"
3. Connect your GitHub repo
4. Set build command: `pip install -r requirements.txt`
5. Set start command: `gunicorn email_verifier:app`
6. Copy your Render URL

## How to call from Apps Script

```javascript
function findEmail(domain, first, last) {
  var url = 'https://YOUR-APP-URL/api/find-email';
  
  var response = UrlFetchApp.fetch(url, {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify({
      domain: domain,
      first: first,
      last: last
    }),
    muteHttpExceptions: true
  });
  
  return JSON.parse(response.getContentText());
}
```

## Example Response from /api/find-email

```json
{
  "domain": "company.com",
  "first": "John",
  "last": "Smith",
  "valid_email": "john.smith@company.com",
  "status": "Found",
  "error": null,
  "all_permutations": [
    "john@company.com",
    "smith@company.com",
    "john.smith@company.com",
    ...
  ],
  "permutations_tried": 3
}
```

## Status Values

- `Found` — Valid email confirmed via SMTP
- `Risky` — Server blocked verification (might be valid)
- `Not Found` — No valid permutation found
- `No MX Records` — Domain has no email server
- `Error` — Missing input data
