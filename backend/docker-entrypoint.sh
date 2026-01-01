#!/bin/bash
set -e

echo "Starting TrustCore Backend..."

# Wait for database to be ready
echo "Waiting for database..."
until PGPASSWORD=${POSTGRES_PASSWORD:-kwn09j2pkmwffd} psql -h ${POSTGRES_HOST:-trustcore_db} -U ${POSTGRES_USER:-trustcore} -d ${POSTGRES_DB:-trustcore} -c '\q' 2>/dev/null; do
  echo "Database is unavailable - sleeping"
  sleep 1
done

echo "Database is up!"

# Run migrations
echo "Running database migrations..."
alembic upgrade head

# Initialize CA
echo "Initializing Certificate Authority..."
python -c "from app.services.ca_service import ca_service; ca_service.initialize_ca()" || echo "CA already initialized"

# Start application
echo "Starting application..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload