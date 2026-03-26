---
name: docker-helper
description: Shortcuts for managing Docker containers and images
version: 1.3.0
metadata:
  openclaw:
    requires:
      bins:
        - docker
---

# Docker Helper

Manage Docker containers easily.

## Usage

List running containers:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Clean up unused images:

```bash
docker image prune -f
```
