import pytest
import os
import sys

# Add the backend directory to Python path so tests can import app.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
