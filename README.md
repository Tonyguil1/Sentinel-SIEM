# Sentinel-SIEM

Sentinel is a Linux security monitoring platform
written in Python.

## Features
- SSH authentication log collection
- Detection of failed logins, successful logins,
  invalid usernames, and pre-authentication disconnects
- JSON event normalization
- Continuous Linux log monitoring
- Agent forwards events to a central API, buffering
  them locally while the API is unavailable
- API-key authenticated FastAPI backend
- PostgreSQL event storage
- systemd service integration

## Technology
- Python
- Ubuntu Linux
- systemd
- FastAPI
- PostgreSQL


## Project Status
- Part 1: Linux Security Monitoring Agent
- Part 2: Event ingestion API and database
