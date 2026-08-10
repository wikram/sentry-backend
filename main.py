#!/usr/bin/env python3
"""Main entry point for the Sentry DevOps Incident Analyzer.

Provides both CLI and REST API interfaces for the incident analysis workflow:
1. Loads raw logs from a file or API request
2. Classifies log entries by severity and category
3. Generates remediation steps
4. Routes to downstream agents (cookbook, Slack, JIRA) based on severity
5. Outputs analysis results

USAGE:

  REST API Server (Uvicorn):
    uvicorn main:app --reload
    uvicorn main:app --host 0.0.0.0 --port 8000
    
  REST API Server (Direct):
    python main.py --server
    python main.py --server --host 0.0.0.0 --port 8000

  CLI Analysis:
    python main.py sample_logs/app_errors.csv
    python main.py sample_logs/k8s_crash.json --json
    python main.py logs/production.log --output results.json

API Endpoints:
  GET  /api/health           - Health check
  POST /api/analyze          - Analyze logs (JSON)
  POST /api/analyze-file     - Analyze uploaded log files
  GET  /docs                 - Interactive API documentation (Swagger UI)
  GET  /redoc                - Alternative API documentation (ReDoc)
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from logger import configure_logging
from utils.db import init_database, close_database
from utils.helpers import get_llm_config, load_logs, run_analysis, display_results
from api import router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# FastAPI app initialization
app = FastAPI(
    title="Sentry Incident Analyzer API",
    description="AI-powered incident analysis and remediation workflow",
    version="1.0.0",
)

# CORS middleware for React UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this based on your React UI domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.on_event("startup")
async def startup_event():
    """Log startup event when app starts."""
    # Configure logging from config.yaml
    configure_logging()

    # Initialize database if enabled
    db_connected = init_database()

    logger.info("=" * 80)
    logger.info("Sentry Incident Analyzer API Server Started")
    logger.info("=" * 80)
    logger.info("📚 Interactive API docs available at: http://localhost:8000/docs")
    logger.info("📘 Alternative docs available at: http://localhost:8000/redoc")
    logger.info("❤️  Health check: http://localhost:8000/api/health")
    if db_connected:
        from utils.db import get_database
        db = get_database()
        host = db.config.get("host", "localhost")
        port = db.config.get("port", 5432)
        db_name = db.config.get("name", "sentry")
        logger.info(f"🟢 Database Status: Connected successfully ({db_name} @ {host}:{port})")

    # Resolve LLM model & temperature (.env first, DB fallback).
    llm_cfg = get_llm_config()
    logger.info(f"🤖 LLM Model: {llm_cfg['model'] or 'NOT CONFIGURED'}")
    logger.info(f"🌡️  Temperature: {llm_cfg['temperature']}")

    logger.info("=" * 80)


@app.on_event("shutdown")
async def shutdown_event():
    """Log shutdown event when app stops."""
    # Close database connections
    close_database()

    logger.info("=" * 80)
    logger.info("Sentry Incident Analyzer API Server Stopped")
    logger.info("=" * 80)


def main():
    """Main entry point for the incident analyzer."""
    # Configure logging from config.yaml
    configure_logging()

    parser = argparse.ArgumentParser(
        description="Sentry DevOps Incident Analyzer - CLI and REST API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
QUICK START:

  1. Start REST API Server (Recommended):
     uvicorn main:app --reload
     
  2. Or start with Python:
     python main.py --server
     
  3. Run CLI analysis:
     python main.py sample_logs/app_errors.csv
     python main.py sample_logs/k8s_crash.json --json
     python main.py logs/production.log --output results.json

API Documentation:
  After starting the server, visit: http://localhost:8000/docs
        """,
    )

    parser.add_argument(
        "log_file",
        nargs="?",
        help="Path to the log file to analyze (.log, .txt, .json, or .csv)",
    )
    parser.add_argument(
        "--server",
        action="store_true",
        help="Run as FastAPI server (alternative to using: uvicorn main:app)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Server host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Server port (default: 8000)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of formatted text (CLI only)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Save results to a JSON file (CLI only)",
        metavar="FILE",
    )

    args = parser.parse_args()

    # Server mode
    if args.server:
        logger.info(f"Starting Sentry Incident Analyzer API server on {args.host}:{args.port}")
        print(f"\n🚀 API Server starting at http://{args.host}:{args.port}")
        print(f"📚 API Documentation at http://{args.host}:{args.port}/docs")
        print(f"   Press Ctrl+C to stop\n")
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="info"
        )
        return 0

    # CLI mode
    if not args.log_file:
        parser.print_help()
        print("\n" + "=" * 80)
        print("To run the REST API server, use one of:")
        print("  1. uvicorn main:app --reload")
        print("  2. python main.py --server")
        print("=" * 80)
        return 1

    try:
        # Load logs
        raw_logs = load_logs(args.log_file)

        # Run analysis
        result = run_analysis(raw_logs)

        # Display or save results
        if args.json:
            output = json.dumps(result, indent=2, default=str)
            print(output)
        else:
            display_results(result)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(result, f, indent=2, default=str)
            logger.info(f"Results saved to {output_path}")

        return 0

    except FileNotFoundError as e:
        logger.error(f"File error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())