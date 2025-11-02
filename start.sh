#!/bin/bash

# Start script for Django Keycloak demo

set -e

echo "🚀 Starting Django Keycloak Demo..."
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    echo "Using existing virtual environment..."
    source venv/bin/activate
fi

# Run migrations
echo "Running database migrations..."
python manage.py migrate

# Start Django server
echo "Starting Django server on http://localhost:8010..."
python manage.py runserver 0.0.0.8010