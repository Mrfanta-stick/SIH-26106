import os
from dotenv import load_dotenv

from .graph_builders import build_routing_graph
from .attachment_parser import analyze_attachment_parts
from app.network.ingest import EmailPayload

load_dotenv()

def integrate(payload: bytes, parsed: EmailPayload, vt_api_key=None):
    graph_results = build_routing_graph(payload)
    attachment_results = analyze_attachment_parts(
        ((
            attachment.filename,
            attachment.content_type,
            attachment.data,
        ) for attachment in parsed.attachments),
        vt_api_key,
    )

    master_json = {
        "stage4_analysis": {
            "fingerprint": graph_results.get("fingerprint", {}),
            "routing_graph": graph_results.get("routing_graph", {}),
            "attachments": attachment_results.get("attachments", [])
        }
    }

    return master_json
