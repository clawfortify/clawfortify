---
name: api-client
description: Generic REST API client for testing endpoints
version: 1.0.0
metadata:
  openclaw:
    requires:
      bins:
        - curl
---

# API Client

Test REST API endpoints quickly.

## Usage

```bash
curl -s -X GET "https://api.example.com/users" -H "Accept: application/json" | jq .
```
