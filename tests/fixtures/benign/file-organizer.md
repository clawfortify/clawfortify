---
name: file-organizer
description: Organize files in directories by type, date, or custom rules
version: 1.0.0
---

# File Organizer

Sort and organize files in your downloads folder automatically.

## Usage

```bash
mkdir -p ~/Documents/sorted/{images,docs,videos}
find ~/Downloads -name "*.jpg" -exec mv {} ~/Documents/sorted/images/ \;
find ~/Downloads -name "*.pdf" -exec mv {} ~/Documents/sorted/docs/ \;
```
