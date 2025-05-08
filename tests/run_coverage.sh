#!/bin/bash
# Run tests with coverage for the cryptominer detection module

# Add src directory to PYTHONPATH for import statements to work
export PYTHONPATH=$PYTHONPATH:$(pwd)

# Create a virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r tests/requirements.txt

# Run tests with coverage
echo "Running tests with coverage..."
python tests/run_tests.py --html coverage_html --verbose

# Display results
echo "Test run complete."
echo "HTML coverage report is available in coverage_html/index.html"
echo "To view coverage report: open coverage_html/index.html"

# Deactivate virtual environment
deactivate