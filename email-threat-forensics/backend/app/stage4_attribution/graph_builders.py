import email
from email import policy
from email.utils import parsedate_to_datetime
import re
from pathlib import Path
from app.network.hop_tracer import trace
import ipaddress

# noinspection PyProtectedMember
from app.network.domain_geo import _geo_lookup, _asn_lookup

_RE_BY_IP = re.compile(r'\bby\s+\S+\s*\(\[?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\]?\)?')

def extract_by_ip(raw):
    m = _RE_BY_IP.search(raw)
    return m.group("ip") if m else None

def is_public_ip(ip_str):
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (addr.is_private or addr.is_loopback or addr.is_multicast
                     or addr.is_link_local or addr.is_reserved or addr.is_unspecified)
    except ValueError:
        return False

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
    except Exception:
        return 0


def build_routing_graph(eml_file_path):
    with open(eml_file_path, 'rb') as f:
        payload_bytes = f.read()

    msg = email.message_from_bytes(payload_bytes, policy=policy.default)

    dkim_header = msg.get("DKIM-Signature", "")
    domain_match = re.search(r'd=([^;\s]+)', dkim_header)
    selector_match = re.search(r's=([^;\s]+)', dkim_header)

    fingerprint = {
        "reply_to": msg.get("Reply-To", "None"),
        "dkim_domain": domain_match.group(1) if domain_match else "None",
        "dkim_selector": selector_match.group(1) if selector_match else "None"
    }

    team_hops = trace(payload_bytes)

    if not team_hops:
        return {"fingerprint": fingerprint, "routing_graph": {"nodes": [], "edges": []}}

    nodes, edges, seen_nodes, node_counter = [], [], set(), 1

    current_dir = Path(__file__).resolve().parent
    data_dir_path = current_dir.parent / "data"
    city_db = data_dir_path / "GeoLite2-City.mmdb"
    asn_db = data_dir_path / "GeoLite2-ASN.mmdb"

    def add_node(raw_name, fallback_ip, is_public_ip, node_type="mta"):
        nonlocal node_counter
        cleaned_name = clean_hostname(raw_name) if raw_name else fallback_ip or "Unknown"

        if cleaned_name not in seen_nodes:
            if not is_public_ip:
                country, asn, lat, lon = "Internal", "Private Network", 0.0, 0.0
            else:
                ip_to_check = fallback_ip if fallback_ip else (
                    cleaned_name if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', cleaned_name) else "")

                c_iso, _, lat, lon = _geo_lookup(ip_to_check, city_db)
                a_num, _ = _asn_lookup(ip_to_check, asn_db)

                country = c_iso if c_iso != "XX" else "Unknown"
                asn = a_num if a_num != "AS0" else "Unknown"

            nodes.append({
                "id": f"node{node_counter}",
                "label": cleaned_name,
                "type": node_type,
                "data": {
                    "country": country,
                    "asn": asn,
                    "latitude": lat,
                    "longitude": lon
                }
            })

            seen_nodes.add(cleaned_name)
            node_counter += 1

        return next(n["id"] for n in nodes if n["label"] == cleaned_name)

    for i, hop in enumerate(team_hops):
        is_last_hop = (i == len(team_hops) - 1)
        current_node_type = "destination" if is_last_hop else "mta"

        by_ip = extract_by_ip(hop.raw)
        current_node_id = add_node(hop.by_host, hop.ip, hop.is_public(), current_node_type)

        protocol_match = re.search(r'\bwith\s+([a-zA-Z0-9_\-]+)', hop.raw, re.IGNORECASE)
        protocol_used = protocol_match.group(1).strip().upper() if protocol_match else "SMTP"
        is_secure = protocol_used.endswith("S")

        edge_data = {
            "is_encrypted": is_secure,
            "threat_level": "low" if is_secure else "medium"
        }

        if i == 0:
            origin_id = add_node(hop.hostname, hop.ip, hop.is_public(), "origin")
            edges.append({
                "from": origin_id,
                "to": current_node_id,
                "protocol": protocol_used,
                "latency_sec": 0,
                "data": edge_data
            })

        if i > 0:
            prev_hop = team_hops[i - 1]
            prev_by_ip = extract_by_ip(prev_hop.raw)
            prev_node_id = add_node(prev_hop.by_host, prev_by_ip, is_public_ip(prev_by_ip))
            latency = calculate_latency(prev_hop.timestamp_hint, hop.timestamp_hint)

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