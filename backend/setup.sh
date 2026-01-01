#!/bin/bash

echo "========================================="
echo "TrustCore Setup Script"
echo "========================================="
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "Creating .env from example..."
    cp .env.example .env
    echo "⚠️  Please edit .env and configure your OIDC provider details"
    echo ""
fi

# Check if backend/.env exists
if [ ! -f backend/.env ]; then
    echo "Creating backend/.env from example..."
    cp backend/.env.example backend/.env
    
    # Generate a random secret key
    SECRET_KEY=$(openssl rand -hex 32)
    
    # Update the secret key in backend/.env
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/change-this-to-a-random-secret-key/$SECRET_KEY/" backend/.env
    else
        # Linux
        sed -i "s/change-this-to-a-random-secret-key/$SECRET_KEY/" backend/.env
    fi
    
    echo "✓ Generated random SECRET_KEY"
    echo "⚠️  Please edit backend/.env and configure your settings"
    echo ""
fi

echo "========================================="
echo "Configuration files created!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Edit .env and configure OIDC settings"
echo "2. Edit backend/.env and review CA settings"
echo "3. Run: docker-compose up -d"
echo "4. Access API docs at: http://localhost:8000/api/v1/docs"
echo ""
echo "For detailed instructions, see README.md"
echo ""