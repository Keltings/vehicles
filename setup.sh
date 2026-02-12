#!/bin/bash

# Vehicle Intelligence Platform - Setup Script
echo "=========================================="
echo "Vehicle Intelligence Platform Setup"
echo "=========================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed!"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

echo "✅ Python found: $(python3 --version)"
echo ""

# Create virtual environment
#echo "📦 Creating virtual environment..."
#python3 -m venv venv

# Activate virtual environment
#echo "🔌 Activating virtual environment..."
#source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Initialize Django project
echo "🚀 Initializing Django project..."
django-admin startproject vehicle_project .

# Create intelligence app
echo "📁 Creating intelligence app..."
python manage.py startapp intelligence

# Run initial migrations
echo "🗃️  Running initial migrations..."
python manage.py migrate

# Create superuser (will prompt)
echo ""
echo "=========================================="
echo "Creating Admin User"
echo "=========================================="
python manage.py createsuperuser

# Import CSV data (if exists)
if [ -f "vehicle_data.csv" ]; then
    echo ""
    echo "📊 Importing vehicle data from CSV..."
    python manage.py import_vehicles
else
    echo ""
    echo "⚠️  No vehicle_data.csv found"
    echo "Place your CSV file in the root directory and run:"
    echo "python manage.py import_vehicles"
fi

echo ""
echo "=========================================="
echo "✅ Setup Complete!"
echo "=========================================="
echo ""
echo "To start the server:"
echo "  source venv/bin/activate"
echo "  python manage.py runserver"
echo ""
echo "Then visit: http://127.0.0.1:8000/intelligence/"
echo ""