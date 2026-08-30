import email
from email import policy
from email.utils import parsedate_to_datetime
import re
import geoip2.database


# noinspection PyBroadException
def get_ip_info(ip_address):
    if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172."):
        return {"country": "Internal", "asn": "Private Network", "lat": 0.0, "lon": 0.0}

    if not re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ip_address):
        return {"country": "N/A", "asn": "N/A", "lat": 0.0, "lon": 0.0}

    ip_data = {"country": "Unknown", "asn": "Unknown", "lat": 0.0, "lon": 0.0}

    try:
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city(ip_address)
            if response.country.iso_code:
                ip_data["country"] = response.country.iso_code
            if response.location.latitude and response.location.longitude:
                ip_data["lat"] = response.location.latitude
                ip_data["lon"] = response.location.longitude
    except Exception:
        pass
    try:
        with geoip2.database.Reader('GeoLite2-ASN.mmdb') as reader:
            response = reader.asn(ip_address)
            if response.autonomous_system_number:
                ip_data["asn"] = f"AS{response.autonomous_system_number}"
    except Exception:
        pass

    return ip_data


def clean_hostname(raw_string):
    if not raw_string:
        return "Unknown"
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_string)
    if ip_match:
        return ip_match.group(0)
    return raw_string.split()[0]


# noinspection PyBroadException
def calculate_latency(time1_str, time2_str):
    if not time1_str or not time2_str:
        return 0
    try:
        time1 = parsedate_to_datetime(time1_str)
        time2 = parsedate_to_datetime(time2_str)
        diff = (time2 - time1).total_seconds()
        return max(0, int(diff))
    except Exception as e:
        return 0


def build_routing_graph(eml_file_path):
    with open(eml_file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    dkim_header = msg.get("DKIM-Signature", "")
    domain_match = re.search(r'd=([^;\s]+)', dkim_header)
    selector_match = re.search(r's=([^;\s]+)', dkim_header)

    fingerprint = {
        "reply_to": msg.get("Reply-To", "None"),
        "dkim_domain": domain_match.group(1) if domain_match else "None",
        "dkim_selector": selector_match.group(1) if selector_match else "None"
    }

    received_headers = msg.get_all("Received")
    if not received_headers:
        return {"fingerprint": fingerprint, "routing_graph": {"nodes": [], "edges": []}}

    regex = re.compile(
        r'(?:from\s+(?P<from>.*?)\s*(?=\bby\b|\bwith\b|\bid\b|;))?'
        r'(?:by\s+(?P<by>.*?)\s*(?=\bwith\b|\bid\b|;))?'
        r'(?:with\s+(?P<with>.*?)\s*(?=\bid\b|;))?'
        r'(?:id\s+.*?)?'
        r';\s*(?P<date>.*)',
        re.IGNORECASE
    )

    parsed_hops = []
    for header in received_headers:
        cleaned_header = " ".join(header.split())
        match = regex.search(cleaned_header)
        if match:
            parsed_hops.append({
                "from": match.group("from"),
                "by_host": match.group("by"),
                "protocol": match.group("with") if match.group("with") else "SMTP",
                "timestamp": match.group("date")
            })

    chronological_hops = list(reversed(parsed_hops))
    nodes, edges, seen_nodes, node_counter = [], [], set(), 1

    def add_node(raw_name, node_type="mta"):
        nonlocal node_counter
        cleaned_name = clean_hostname(raw_name)

        if cleaned_name not in seen_nodes:
            ip_data = get_ip_info(cleaned_name)

            nodes.append({
                "id": f"node{node_counter}",
                "label": cleaned_name,
                "type": node_type,
                "data": {
                    "country": ip_data["country"],
                    "asn": ip_data["asn"],
                    "latitude": ip_data["lat"],
                    "longitude": ip_data["lon"]
                }
            })

            seen_nodes.add(cleaned_name)
            node_counter += 1

        return next(n["id"] for n in nodes if n["label"] == cleaned_name)

    for i, hop in enumerate(chronological_hops):
        # If it's the very last hop in the list, label it "destination", otherwise "mta"
        is_last_hop = (i == len(chronological_hops) - 1)
        current_node_type = "destination" if is_last_hop else "mta"

        current_node_id = add_node(hop["by_host"], current_node_type)

        protocol_used = hop["protocol"].strip().upper()
        is_secure = protocol_used.endswith("S")
        edge_data = {
            "is_encrypted": is_secure,
            "threat_level": "low" if is_secure else "medium"
        }

        if i == 0 and hop["from"]:
            # The very first 'from' server is the attacker! Label it "origin"
            origin_id = add_node(hop["from"], "origin")
            edges.append({
                "from": origin_id,
                "to": current_node_id,
                "protocol": protocol_used,
                "latency_sec": 0,
                "data": edge_data
            })

        if i > 0:
            prev_hop = chronological_hops[i - 1]
            prev_node_id = add_node(prev_hop["by_host"])  # Defaults to "mta"
            latency = calculate_latency(prev_hop["timestamp"], hop["timestamp"])

            edges.append({
                "from": prev_node_id,
                "to": current_node_id,
                "protocol": protocol_used,
                "latency_sec": latency,
                "data": edge_data
            })

    return {
        "fingerprint": fingerprint,
        "routing_graph": {
            "nodes": nodes,
            "edges": edges
        }
    }


""" Sample JSON has Fingerprints section. That is not to be plotted on FRONTEND. """
