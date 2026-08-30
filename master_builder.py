import json
from graph_builders import build_routing_graph
from attachment_parser import analyze_attachments
from dotenv import load_dotenv
import os
from pathlib import Path

load_dotenv()

current_directory = Path(__file__).parent
env_path = current_directory / '.env'
load_dotenv(dotenv_path=env_path)

# .env resides in stage4/.env

def run_stage4_analysis(eml_file_path, vt_api_key=None):
    graph_results = build_routing_graph(eml_file_path)
    attachment_results = analyze_attachments(eml_file_path, vt_api_key)

    master_json = {
        "stage4_analysis": {
            "fingerprint": graph_results.get("fingerprint", {}),
            "routing_graph": graph_results.get("routing_graph", {}),
            "attachments": attachment_results.get("attachments", [])
        }
    }

    return master_json

if __name__ == "__main__":
    TARGET_EMAIL = "tests/master.eml"
    VT_KEY = os.getenv("VT_API_KEY", "NOT_FOUND")

    final_output = run_stage4_analysis(TARGET_EMAIL, VT_KEY)
    print(json.dumps(final_output, indent=2))