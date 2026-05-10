import json
import logging
import os
import time
from jira import JIRA
from jira.exceptions import JIRAError
from langchain_core.messages import SystemMessage, HumanMessage
from orchestrator.state import IncidentState
from utils.llm import get_llm
from services.prompt_loader import load_prompt

logger = logging.getLogger(__name__)

# Set up root logger if not already configured
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.FileHandler("jira_ticket_debug.log"),
        logging.StreamHandler()
    ]
)

JIRA_SYSTEM_PROMPT = load_prompt('tira_ticket.md')


def _validate_jira_config():
    """Validate JIRA configuration from environment variables."""
    config = {
        "url": os.environ.get("JIRA_INSTANCE_URL", "").strip(),
        "email": os.environ.get("JIRA_USER_EMAIL", "").strip(),
        "token": os.environ.get("JIRA_API_TOKEN", "").strip(),
        "project_key": os.environ.get("JIRA_PROJECT_KEY", "").strip(),
    }
    
    missing = [k for k, v in config.items() if not v]
    if missing:
        logger.error("JIRA configuration incomplete. Missing: %s", ", ".join(missing))
        logger.error("Please configure in .env: JIRA_INSTANCE_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY")
        return None
    
    # Validate project key format (should be 2-4 uppercase letters, not an issue ID)
    project_key = config["project_key"]
    if not (2 <= len(project_key) <= 4 and project_key.isupper() and project_key.isalpha()):
        logger.error("JIRA_PROJECT_KEY should be 2-4 uppercase letters (e.g., 'OPS', 'DEV'), not an issue ID")
        return None
    logger.info("JIRA config validated. URL: %s, Project: %s", config["url"], project_key)
    return config

def _get_jira_client():
    """Initialize and return JIRA client using environment variables."""
    config = _validate_jira_config()
    if not config:
        return None
    
    try:
        client = JIRA(
            server=config["url"],
            basic_auth=(config["email"], config["token"]),
            options={"agile_rest_path": "agile/1.0"}
        )
        logger.info("✓ Successfully connected to JIRA at %s", config["url"])
        return client
    except JIRAError as e:
        logger.error("✗ JIRA authentication failed: %s", str(e))
        logger.error("  Check your JIRA_USER_EMAIL and JIRA_API_TOKEN")
        return None
    except Exception as e:
        logger.error("✗ Failed to connect to JIRA: %s", str(e))
        return None


def _create_jira_ticket(jira_client, ticket_data):
    """Create a single JIRA ticket in the configured project."""
    if not jira_client:
        logger.error("JIRA client not initialized")
        return None
    
    try:
        project_key = os.environ.get("JIRA_PROJECT_KEY", "").strip()
        
        # Priority mapping
        priority_map = {
            "Critical": "Highest",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
        }
        
        # Prepare issue fields
        issue_dict = {
            "project": {"key": project_key},
            "summary": ticket_data.get("title", "Incident Alert"),
            "description": ticket_data.get("description", "No description provided"),
            "issuetype": {"name": ticket_data.get("issue_type", "Task")},
            "priority": {"name": priority_map.get(ticket_data.get("priority", "High"), "High")},
        }
        
        # Add labels if present
        labels = ticket_data.get("labels", [])
        if labels and isinstance(labels, list):
            issue_dict["labels"] = labels
        
        logger.debug("Creating JIRA ticket with: %s", json.dumps(issue_dict, indent=2))
        
        issue = jira_client.create_issue(fields=issue_dict)
        jira_url = os.environ.get("JIRA_INSTANCE_URL", "").strip()
        ticket_url = f"{jira_url}/browse/{issue.key}"
        
        logger.info("✓ Created JIRA ticket: %s (%s)", issue.key, ticket_url)
        
        return {
            "key": issue.key,
            "url": ticket_url,
            "title": ticket_data.get("title"),
            "priority": ticket_data.get("priority"),
            "status": "created"
        }
    except JIRAError as e:
        logger.error("✗ JIRA API error creating ticket: %s", str(e))
        if "valid project" in str(e).lower():
            logger.error("  Ensure JIRA_PROJECT_KEY is correct (should be 2-4 uppercase letters like 'OPS', 'DEV')")
        return None
    except Exception as e:
        logger.error("✗ Unexpected error creating JIRA ticket: %s", str(e))
        return None


def create_jira_tickets(state: IncidentState) -> dict:
    """Create JIRA tickets for CRITICAL and HIGH severity issues.

    Filters remediations linked to high-severity log entries, generates
    structured ticket data using LLM, and creates actual JIRA tickets.

    Args:
        state: Current incident state containing classified_entries and remediations.

    Returns:
        Dict with jira_tickets and agent_trace updates.
    """
    start_time = time.time()

    # Get classified entries and remediations
    classified_entries = state.get("classified_entries", [])
    remediations = state.get("remediations", [])
    
    if not classified_entries or not remediations:
        logger.warning("No classified entries or remediations found — skipping JIRA ticket creation")
        end_time = time.time()
        return {
            "jira_tickets": [],
            "agent_trace": [{
                "agent_name": "jira_ticket",
                "start_time": start_time,
                "end_time": end_time,
                "input_summary": "Insufficient data (no entries or remediations)",
                "output_summary": "Skipped - no data to process",
                "status": "skipped",
            }],
        }

    # Identify CRITICAL and HIGH severity entries
    high_sev_indices = set()
    critical_count = 0
    high_count = 0
    
    for i, entry in enumerate(classified_entries):
        severity = entry.get("severity", "").upper()
        if severity == "CRITICAL":
            high_sev_indices.add(i)
            critical_count += 1
        elif severity == "HIGH":
            high_sev_indices.add(i)
            high_count += 1
    
    logger.info("Found %d CRITICAL and %d HIGH severity entries", critical_count, high_count)
    
    # Filter remediations linked to CRITICAL/HIGH entries
    critical_remediations = [
        rem for rem in remediations
        if any(idx in high_sev_indices for idx in rem.get("linked_log_entries", []))
    ]

    if not critical_remediations:
        logger.warning("No remediations linked to CRITICAL/HIGH entries — skipping JIRA ticket creation")
        end_time = time.time()
        return {
            "jira_tickets": [],
            "agent_trace": [{
                "agent_name": "jira_ticket",
                "start_time": start_time,
                "end_time": end_time,
                "input_summary": f"Found {len(classified_entries)} entries but no critical remediations",
                "output_summary": "No critical remediations to create tickets for",
                "status": "completed",
            }],
        }

    logger.info("Generating JIRA tickets for %d critical/high remediations", len(critical_remediations))

    # Use LLM to generate ticket specifications
    try:
        llm = get_llm()
        remediations_json = json.dumps(critical_remediations, indent=2)
        messages = [
            SystemMessage(content=JIRA_SYSTEM_PROMPT),
            HumanMessage(content=f"Create JIRA tickets for these remediations:\n\n{remediations_json}"),
        ]
        response = llm.invoke(messages)

        raw_content = response.content.strip()
        if raw_content.startswith("```"):
            raw_content = raw_content.split("\n", 1)[1].rsplit("```", 1)[0].strip()

        ticket_specs = json.loads(raw_content)
        logger.info("LLM generated %d ticket specifications", len(ticket_specs))
    except json.JSONDecodeError as e:
        logger.error("Failed to parse LLM response as JSON: %s", e)
        logger.debug("Raw LLM response: %s", raw_content if 'raw_content' in locals() else "N/A")
        raise
    except Exception as e:
        logger.error("Error generating ticket specifications: %s", e)
        raise

    # Connect to JIRA and create actual tickets
    created_tickets = []
    jira_client = _get_jira_client()
    
    if jira_client:
        logger.info("JIRA client connected - attempting to create %d tickets", len(ticket_specs))
        for idx, ticket_spec in enumerate(ticket_specs, 1):
            logger.info("Creating ticket %d/%d: %s", idx, len(ticket_specs), ticket_spec.get("title", "Unknown"))
            result = _create_jira_ticket(jira_client, ticket_spec)
            if result:
                created_tickets.append(result)
            else:
                created_tickets.append({
                    "title": ticket_spec.get("title"),
                    "status": "failed",
                    "error": "Failed to create ticket in JIRA"
                })
    else:
        logger.warning("JIRA client unavailable - running in mock mode")
        logger.warning("Check JIRA configuration in .env file")
        # Mock mode - create placeholder tickets for testing
        for i, ticket_spec in enumerate(ticket_specs):
            created_tickets.append({
                "key": f"MOCK-{i + 1}",
                "title": ticket_spec.get("title"),
                "status": "mocked",
                "message": "JIRA credentials not configured or invalid"
            })

    end_time = time.time()
    successful = sum(1 for t in created_tickets if t.get("status") == "created")
    failed = sum(1 for t in created_tickets if t.get("status") == "failed")
    mocked = sum(1 for t in created_tickets if t.get("status") == "mocked")
    
    logger.info("JIRA ticket creation complete: %d created, %d failed, %d mocked", successful, failed, mocked)

    trace_entry = {
        "agent_name": "jira_ticket",
        "start_time": start_time,
        "end_time": end_time,
        "input_summary": f"Critical/High remediations: {len(critical_remediations)} items",
        "output_summary": f"Created {successful} tickets, {failed} failed, {mocked} mocked",
        "status": "completed",
    }

    return {
        "jira_tickets": created_tickets,
        "agent_trace": [trace_entry],
    }