'use client';

export default function CyberKillChain({ stages = null }) {
  // Default enterprise stages if not passed
  const defaultStages = [
    { name: '1. Reconnaissance', count: 128, severity: 'LOW', color: '#10b981', status: 'Monitored', desc: 'Port scans & service probes' },
    { name: '2. Exploitation', count: 42, severity: 'MEDIUM', color: '#f59e0b', status: 'Mitigated', desc: 'RCE & brute force attempts' },
    { name: '3. Lateral Pivot', count: 14, severity: 'HIGH', color: '#f97316', status: 'Intercepted', desc: 'Internal credential relay' },
    { name: '4. C2 Beaconing', count: 5, severity: 'HIGH', color: '#a855f7', status: 'Terminated', desc: 'Cobalt Strike DNS beacons' },
    { name: '5. Exfiltration', count: 1, severity: 'CRITICAL', color: '#ef4444', status: 'Blocked', desc: 'Large outbound tunnel' },
    { name: '6. Auto-Quarantine', count: 189, severity: 'LOW', color: '#00d4ff', status: 'Enforced', desc: 'Firewall drop applied' },
  ];

  const data = stages || defaultStages;

  return (
    <div className="glass-card" style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: 'var(--accent-cyan)' }}>⚡</span> MITRE ATT&CK & Cyber Kill Chain Trajectory
          </h3>
          <p style={{ margin: '4px 0 0', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Real-time pipeline correlating raw packet traces across progressive adversary attack stages
          </p>
        </div>
        <span style={{ fontSize: '0.75rem', padding: '4px 10px', borderRadius: 20, background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.3)', fontWeight: 600 }}>
          🛡️ Kill Chain Intercept Active
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, position: 'relative' }}>
        {data.map((stage, i) => (
          <div
            key={i}
            style={{
              background: 'rgba(255, 255, 255, 0.02)',
              border: `1px solid ${stage.color}33`,
              borderRadius: 12,
              padding: '14px 14px 12px',
              position: 'relative',
              overflow: 'hidden',
              transition: 'all 0.2s ease',
            }}
          >
            {/* Top Accent Line */}
            <div style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: 3,
              background: `linear-gradient(90deg, ${stage.color}, transparent)`,
            }} />

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                {stage.name}
              </span>
              <span
                style={{
                  fontSize: '0.65rem',
                  padding: '2px 6px',
                  borderRadius: 4,
                  background: `${stage.color}22`,
                  color: stage.color,
                  fontWeight: 700,
                  border: `1px solid ${stage.color}44`,
                }}
              >
                {stage.status}
              </span>
            </div>

            <div style={{ fontSize: '1.4rem', fontWeight: 900, color: stage.color, margin: '6px 0 2px' }}>
              {stage.count}
            </div>

            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', lineHeight: 1.3 }}>
              {stage.desc}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
