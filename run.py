#!/usr/bin/env python3
"""
Main entry point for the AI Agent Permission Guardrail system.

This script provides a command-line interface to run different components
of the system: FastAPI backend, Streamlit dashboard, or tests.
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def run_backend():
    """Start the FastAPI backend server."""
    print("Starting FastAPI backend...")
    print(f"API will be available at http://localhost:8000")
    print(f"API documentation at http://localhost:8000/docs")
    print("Press Ctrl+C to stop the server")
    print("-" * 50)

    # Set environment variable to ensure proper reloading
    os.environ["API_RELOAD"] = "true"

    try:
        subprocess.run([
            sys.executable, "-m", "uvicorn",
            "app.main:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--reload"
        ], check=True)
    except KeyboardInterrupt:
        print("\nBackend server stopped.")
    except subprocess.CalledProcessError as e:
        print(f"Error starting backend: {e}")
        return 1
    return 0

def run_dashboard():
    """Start the Streamlit dashboard."""
    print("Starting Streamlit dashboard...")
    print(f"Dashboard will be available at http://localhost:8501")
    print("Press Ctrl+C to stop the dashboard")
    print("-" * 50)

    try:
        subprocess.run([
            sys.executable, "-m", "streamlit",
            "run", "dashboard/streamlit_app.py",
            "--server.port", "8501",
            "--server.address", "0.0.0.0"
        ], check=True)
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    except subprocess.CalledProcessError as e:
        print(f"Error starting dashboard: {e}")
        return 1
    return 0

def run_tests():
    """Run the test suite."""
    print("Running test suite...")
    print("-" * 50)

    try:
        result = subprocess.run([
            sys.executable, "-m", "pytest",
            "tests/", "-v",
            "--tb=short"
        ], check=False)

        if result.returncode == 0:
            print("\n✅ All tests passed!")
        else:
            print(f"\n❌ Some tests failed (exit code: {result.returncode})")

        return result.returncode
    except Exception as e:
        print(f"Error running tests: {e}")
        return 1

def check_dependencies():
    """Check if required dependencies are installed."""
    print("Checking dependencies...")

    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        return False

    try:
        import fastapi
        import uvicorn
        import pydantic
        import sqlalchemy
        import streamlit
        import pytest
        print("✅ All core dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("\nPlease install dependencies with:")
        print("  pip install -r requirements.txt")
        return False

def setup_environment():
    """Set up the environment."""
    print("Setting up environment...")

    # Create data directory if it doesn't exist
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    print(f"✅ Data directory: {data_dir.absolute()}")

    # Check if .env exists, create from example if not
    env_file = Path(".env")
    env_example = Path(".env.example")

    if not env_file.exists() and env_example.exists():
        import shutil
        shutil.copy(env_example, env_file)
        print("✅ Created .env file from .env.example")
        print("⚠️  Please edit .env to configure your settings")
    elif env_file.exists():
        print("✅ .env file already exists")

    return True

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AI Agent Permission Guardrail System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s backend      # Start FastAPI backend
  %(prog)s dashboard    # Start Streamlit dashboard
  %(prog)s tests        # Run test suite
  %(prog)s all          # Run backend and dashboard together
        """
    )

    parser.add_argument(
        "command",
        choices=["backend", "dashboard", "tests", "all", "setup"],
        help="Command to execute"
    )

    parser.add_argument(
        "--no-check",
        action="store_true",
        help="Skip dependency checks"
    )

    args = parser.parse_args()

    # Change to project directory
    project_dir = Path(__file__).parent
    os.chdir(project_dir)

    print("=" * 60)
    print("AI AGENT PERMISSION GUARDRAIL")
    print("=" * 60)

    if args.command == "setup":
        setup_environment()
        return 0

    if not args.no_check:
        if not check_dependencies():
            return 1

        if not setup_environment():
            return 1

    if args.command == "backend":
        return run_backend()
    elif args.command == "dashboard":
        return run_dashboard()
    elif args.command == "tests":
        return run_tests()
    elif args.command == "all":
        print("Starting both backend and dashboard...")
        print("This will open two terminal windows/tabs")
        print("\nIn one terminal, run:")
        print("  python run.py backend")
        print("\nIn another terminal, run:")
        print("  python run.py dashboard")
        return 0

    return 0

if __name__ == "__main__":
    sys.exit(main())