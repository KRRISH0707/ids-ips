#!/usr/bin/env python3
import json
import urllib.parse
import urllib.request

API_BASE = "http://localhost:8000"

def main():
    print("=" * 65)
    print("VERIFYING ENTERPRISE SOC SUITE MODULES")
    print("=" * 65)

    # 1. Login
    data = urllib.parse.urlencode({
        "username": "krrish183224@gmail.com",
        "password": "183@Krrish"
    }).encode()
    req = urllib.request.Request(
        f"{API_BASE}/api/auth/login",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req) as res:
        token = json.loads(res.read().decode())["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("[1/6] Authentication: SUCCESS (Admin token issued)")

    # 2. Test SOAR Playbooks
    req = urllib.request.Request(f"{API_BASE}/api/soar/playbooks", headers=headers)
    with urllib.request.urlopen(req) as res:
        pbs = json.loads(res.read().decode())
        pb1 = pbs["items"][0]
        print(f"[2/6] SOAR Playbooks: SUCCESS ({pbs['total']} playbooks active | e.g. '{pb1['name']}')")

    # 3. Test SOAR Playbook Execution
    exec_req = urllib.request.Request(
        f"{API_BASE}/api/soar/playbooks/{pb1['id']}/execute",
        data=json.dumps({"target": "192.168.1.150"}).encode(),
        headers={"Content-Type": "application/json", **headers}
    )
    with urllib.request.urlopen(exec_req) as res:
        exec_res = json.loads(res.read().decode())
        print(f"[3/6] SOAR Execution: SUCCESS (Status: {exec_res['status']} | Actions executed: {len(exec_res['actions_taken'])})")

    # 4. Test MITRE ATT&CK Matrix
    m_req = urllib.request.Request(f"{API_BASE}/api/mitre/matrix", headers=headers)
    with urllib.request.urlopen(m_req) as res:
        mitre_data = json.loads(res.read().decode())
        print(f"[4/6] MITRE ATT&CK Matrix: SUCCESS ({len(mitre_data['tactics'])} tactics mapped | Total mapped hits: {mitre_data['total_mapped_detections']})")

    # 5. Test Network Topology Graph
    topo_req = urllib.request.Request(f"{API_BASE}/api/network/topology", headers=headers)
    with urllib.request.urlopen(topo_req) as res:
        topo = json.loads(res.read().decode())
        print(f"[5/6] Network Topology: SUCCESS ({len(topo['nodes'])} nodes | {len(topo['edges'])} edges | Summary: {topo['summary']})")

    # 6. Test Threat Intel Lookup & PCAP DPI Dissection
    ti_req = urllib.request.Request(
        f"{API_BASE}/api/threat-intel/lookup",
        data=json.dumps({"value": "45.33.32.156"}).encode(),
        headers={"Content-Type": "application/json", **headers}
    )
    with urllib.request.urlopen(ti_req) as res:
        ti_res = json.loads(res.read().decode())
        print(f"[6/6] Threat Intel & Reputation: SUCCESS ('45.33.32.156' -> {ti_res['reputation_level']} | Family: {ti_res['threat_family']} | Score: {ti_res['reputation_score']}%)")

    # 7. Test Alert PCAP DPI Trace
    alerts_req = urllib.request.Request(f"{API_BASE}/api/alerts?limit=1", headers=headers)
    with urllib.request.urlopen(alerts_req) as res:
        first_alert = json.loads(res.read().decode())["items"][0]
        dpi_req = urllib.request.Request(f"{API_BASE}/api/alerts/{first_alert['id']}/packet-trace", headers=headers)
        with urllib.request.urlopen(dpi_req) as dpi_res:
            dpi_data = json.loads(dpi_res.read().decode())
            print(f"[7/7] PCAP Deep Packet Inspection: SUCCESS (Protocols: {dpi_data['frame']['protocols']} | Payload Hex Dump lines: {len(dpi_data['payload']['hex_dump'])})")

    print("=" * 65)
    print("ALL ENTERPRISE SOC SUITE MODULES VERIFIED & OPERATIONAL!")
    print("=" * 65)

if __name__ == "__main__":
    main()
