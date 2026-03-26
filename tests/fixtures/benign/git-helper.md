---
name: git-helper
description: Simplifies common git operations with shortcuts
version: 2.1.0
metadata:
  openclaw:
    requires:
      bins:
        - git
---

# Git Helper

Shortcuts for common git workflows.

## Usage

Quick commit:

```bash
git add -A && git commit -m "$MESSAGE"
```

Create branch:

```bash
git checkout -b "$BRANCH_NAME"
```
