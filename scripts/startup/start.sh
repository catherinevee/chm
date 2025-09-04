#!/bin/bash

echo "🚀 Starting Catalyst Health Monitor..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if we want development or production mode
if [ "$1" = "dev" ]; then
    echo "🔧 Starting in DEVELOPMENT mode with hot reloading..."
    docker-compose -f docker-compose.dev.yml up --build
else
    echo "🏭 Starting in PRODUCTION mode..."
    docker-compose up --build
fi
