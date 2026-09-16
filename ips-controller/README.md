# IPS controller

This service should NOT directly execute firewall commands from an untrusted event.

Recommended workflow:

event -> risk engine -> policy engine -> action request -> approval/automation policy -> enforcement adapter -> audit log

Safety requirements:
- allowlists for critical assets
- maximum block duration
- automatic expiry
- dry-run mode
- analyst approval mode
- emergency disable switch
- complete audit trail
- rate limiting
- rollback/bypass procedure
