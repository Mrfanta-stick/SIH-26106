import json
import os
from pathlib import Path
from dotenv import load_dotenv

from .graph_builders import build_routing_graph
from .attachment_parser import analyze_attachments

current_directory = Path(__file__).parent
env_path = current_directory / '.env'
load_dotenv(dotenv_path=env_path)

def integrate(eml_file_path, vt_api_key=None):
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

"""
def main():
    current_directory = Path(__file__).parent
    TARGET_EMAIL = current_directory / "tests" / "master.eml"
    VT_KEY = os.getenv("VT_API_KEY", "NOT_FOUND")
    
    final_output = integrate(TARGET_EMAIL, VT_KEY)
    print(json.dumps(final_output, indent=2))

if __name__ == "__main__":
    main()

"""