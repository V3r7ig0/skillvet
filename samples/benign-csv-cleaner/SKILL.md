---
name: csv-cleaner
description: Clean messy CSV files - trim whitespace, drop empty rows, normalize headers. Use when the user has a CSV that needs tidying before analysis.
allowed-tools: Bash(python3 scripts/clean.py *)
---

# CSV Cleaner

Run `python3 scripts/clean.py <input.csv> <output.csv>` to clean a CSV file.
The script trims whitespace, removes fully empty rows, and lowercases headers.
