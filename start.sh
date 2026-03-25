#!/bin/bash
cd /home/kashif/cluade/infraguard

# Load env vars from .env file (keys stay local, never committed)
export $(cat .env | xargs)

python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
