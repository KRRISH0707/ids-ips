"""
seed_100_plus_iocs.py
Synchronizes 236+ verified Threat Intelligence Indicators of Compromise (IOCs)
across Malicious IPs, Hostile Domains, and Malware Hashes into PostgreSQL.
"""

import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_iocs")

# Add backend directory to path if needed
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

try:
    from app.seed_iocs_data import IOCS_DATA_225, seed_threat_intel_iocs
except ImportError:
    try:
        from seed_iocs_data import IOCS_DATA_225, seed_threat_intel_iocs
    except ImportError:
        logger.error("Could not import seed_threat_intel_iocs from seed_iocs_data")
        sys.exit(1)

CURATED_IOCS = IOCS_DATA_225

def seed(conn=None):
    """Seed threat intel indicators."""
    seed_threat_intel_iocs(conn)

if __name__ == "__main__":
    seed()
