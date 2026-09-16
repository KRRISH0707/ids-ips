"""
Network Topology & Real-Time Lateral Movement Graph API Router
"""

from fastapi import APIRouter, Depends
from ..core.database import get_sync_connection
from ..core.security import get_current_user

router = APIRouter(prefix="/network", tags=["network"])

@router.get("/topology")
def get_network_topology(current_user: dict = Depends(get_current_user)):
    """
    Constructs real-time topology map of network zones, sensors, internal assets,
    external threat actors, and active attack vectors.
    """
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            # Query active sensors
            cur.execute("SELECT id, name, hostname, ip_address::text, status, location FROM sensors")
            sensors = cur.fetchall()

            # Query recent critical alerts to build attack vector links
            cur.execute(
                """
                SELECT id, src_ip::text, dst_ip::text, signature, severity, risk_score, category, timestamp
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 15
                """
            )
            alerts = cur.fetchall()

            # Query blocked IPs
            cur.execute("SELECT ip_address::text FROM blocked_ips WHERE is_active = true")
            blocked_rows = cur.fetchall()
            blocked_ips = {row["ip_address"].split('/')[0] for row in blocked_rows}

    nodes = []
    edges = []
    node_ids = set()

    # 1. Gateway & DMZ Hub
    nodes.append({
        "id": "gateway-core",
        "label": "Enterprise Border Gateway",
        "ip": "10.0.0.1",
        "type": "GATEWAY",
        "zone": "DMZ",
        "status": "ONLINE",
        "x": 300, "y": 180
    })
    node_ids.add("gateway-core")

    # 2. Add Sensors
    for i, s in enumerate(sensors):
        s_ip = str(s["ip_address"]).split('/')[0]
        nodes.append({
            "id": f"sensor-{s['id']}",
            "label": s["hostname"] or s["name"],
            "ip": s_ip,
            "type": "SENSOR",
            "zone": s["location"] or "Internal",
            "status": s["status"],
            "x": 480 + (i * 120),
            "y": 180 + (i % 2 * 90)
        })
        node_ids.add(f"sensor-{s['id']}")
        # Link sensor to gateway
        edges.append({
            "source": "gateway-core",
            "target": f"sensor-{s['id']}",
            "type": "TELEMETRY",
            "status": "HEALTHY"
        })

    # 3. Add Internal Servers / Endpoints
    internal_assets = [
        {"id": "srv-db-01", "label": "Database Primary", "ip": "192.168.1.10", "type": "DATABASE", "zone": "Data Tier", "x": 680, "y": 90},
        {"id": "srv-bastion-01", "label": "SSH Bastion Edge", "ip": "192.168.1.20", "type": "SERVER", "zone": "DMZ", "x": 520, "y": 290},
        {"id": "srv-app-c2", "label": "Core App Host", "ip": "192.168.1.150", "type": "WORKSTATION", "zone": "Internal LAN", "x": 720, "y": 280}
    ]

    for asset in internal_assets:
        # Check if sensor or alert indicates isolation
        is_isolated = any(s["status"] == "ISOLATED" and str(s["ip_address"] or "").startswith(asset["ip"]) for s in sensors)
        nodes.append({
            **asset,
            "status": "ISOLATED" if is_isolated else "ONLINE"
        })
        node_ids.add(asset["id"])
        edges.append({
            "source": "gateway-core",
            "target": asset["id"],
            "type": "INTERNAL_BUS",
            "status": "HEALTHY"
        })

    # 4. Add External Threat Actors & Attack Edges from Alerts
    attacker_idx = 0
    for a in alerts:
        src = a["src_ip"].split('/')[0]
        dst = a["dst_ip"].split('/')[0]
        is_blocked = src in blocked_ips

        attacker_node_id = f"ext-{src}"
        if attacker_node_id not in node_ids:
            nodes.append({
                "id": attacker_node_id,
                "label": f"Attacker ({src})",
                "ip": src,
                "type": "THREAT_ACTOR",
                "zone": "External WAN",
                "status": "BLOCKED" if is_blocked else "ATTACKING",
                "x": 80,
                "y": 80 + (attacker_idx * 75)
            })
            node_ids.add(attacker_node_id)
            attacker_idx += 1

        # Find target node
        target_node = next((n["id"] for n in nodes if n.get("ip") == dst), "gateway-core")

        edges.append({
            "source": attacker_node_id,
            "target": target_node,
            "type": "ATTACK_VECTOR",
            "signature": a["signature"],
            "severity": a["severity"],
            "status": "BLOCKED" if is_blocked else "ACTIVE_ATTACK",
            "timestamp": a["timestamp"].isoformat()
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "total_nodes": len(nodes),
            "total_vectors": len(edges),
            "quarantined_nodes": sum(1 for n in nodes if n.get("status") == "ISOLATED"),
            "blocked_attackers": sum(1 for n in nodes if n.get("status") == "BLOCKED")
        }
    }
