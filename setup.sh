#!/bin/bash

# Setup script for Django Keycloak demo

set -e

echo "🔧 Setting up Django Keycloak Demo..."
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "Please install Python 3 and try again."
    exit 1
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Create environment file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️ Creating environment configuration..."
    cat > .env << EOF
# Django Configuration
SECRET_KEY=django-insecure-change-me-in-production
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1,172.28.136.214

# Keycloak Configuration
KEYCLOAK_SERVER_URL=http://172.28.136.214:8080/
KEYCLOAK_REALM=teki_9
KEYCLOAK_CLIENT_ID=easytask
KEYCLOAK_CLIENT_SECRET=FxGBkGiByZVzoJzVJqLuAXezl0r3FpDa

# Session Configuration
KEYCLOAK_SESSION_TIMEOUT=2592000
KEYCLOAK_TOKEN_REFRESH_THRESHOLD=300
EOF
fi

# Run initial migrations
echo "🗄️ Running initial migrations..."
python manage.py migrate

# Create superuser if needed
echo "👤 Creating superuser (if needed)..."
python manage.py createsuperuser --username admin --email admin@example.com --noinput || true

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Start Keycloak: ./start-keycloak.sh"
echo "2. Configure Keycloak realm and client"
echo "3. Start Django: ./start.sh"
echo ""
echo "Access your app at: http://localhost:8010/"