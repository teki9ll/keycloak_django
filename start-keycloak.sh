#!/bin/bash

# Start Keycloak container

set -e

echo "🔐 Starting Keycloak container..."
echo ""

# Check if Docker is available
if command -v docker &> /dev/null; then
    echo "Using Docker..."
    CONTAINER_CMD="docker"
elif command -v podman &> /dev/null; then
    echo "Using Podman..."
    CONTAINER_CMD="podman"
else
    echo "❌ Neither Docker nor Podman found. Please install one of them."
    exit 1
fi

# Remove existing container if it exists
echo "Removing existing Keycloak container..."
$CONTAINER_CMD stop keycloak 2>/dev/null || true
$CONTAINER_CMD rm keycloak 2>/dev/null || true

# Start Keycloak container
echo "Starting Keycloak container on port 8080..."
$CONTAINER_CMD run -d \
  --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin123 \
  -e KC_HEALTH_ENABLED=true \
  quay.io/keycloak/keycloak:23.0.0 \
  start-dev

echo ""
echo "✅ Keycloak container started!"
echo ""
echo "Access Keycloak Admin Console: http://localhost:8080/admin"
echo "Credentials: admin / admin123"
echo ""
echo "Waiting for Keycloak to be ready..."
sleep 10

# Check if Keycloak is ready
for i in {1..30}; do
    if curl -s http://localhost:8080/health/ready > /dev/null; then
        echo "✅ Keycloak is ready!"
        break
    fi
    echo "Waiting for Keycloak... ($i/30)"
    sleep 2
done

if [ $i -eq 30 ]; then
    echo "⚠️ Keycloak may still be starting. Check manually at http://localhost:8080/health/ready"
fi

echo ""
echo "Next steps:"
echo "1. Access Keycloak Admin: http://localhost:8080/admin"
echo "2. Create realm: teki_9"
echo "3. Create client: easytask"
echo "4. Configure redirect URI: http://localhost:8010/callback/"
echo "5. Start Django: ./start.sh"