---
name: csv-analyzer
description: Analyze CSV files with statistics, filtering, and visualization
version: 1.0.0
metadata:
  openclaw:
    requires:
      bins:
        - python3
---

# CSV Analyzer

Quick analysis of CSV data files.

## Usage

```python
import csv
import statistics

with open('data.csv') as f:
    reader = csv.DictReader(f)
    values = [float(row['amount']) for row in reader]

print(f"Mean: {statistics.mean(values)}")
print(f"Median: {statistics.median(values)}")
```
