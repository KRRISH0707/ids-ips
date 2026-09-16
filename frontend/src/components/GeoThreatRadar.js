'use client';

export default function GeoThreatRadar({ origins = null, targets = null }) {
  const defaultOrigins = [
    { country: 'Eastern Europe / RU', flag: '🇷🇺', ip: '185.220.101.5', asn: 'AS9009 Tor Exit', hits: '1,420 pkts/s', sev: 'CRITICAL' },
    { country: 'East Asia / CN', flag: '🇨🇳', ip: '45.33.32.156', asn: 'AS4134 Chinanet', hits: '980 pkts/s', sev: 'HIGH' },
    { country: 'Western Europe / NL', flag: '🇳🇱', ip: '198.51.100.42', asn: 'AS16276 OVH SAS', hits: '520 pkts/s', sev: 'MEDIUM' },
    { country: 'North America / US', flag: '🇺🇸', ip: '203.0.113.15', asn: 'AS14061 DigitalOcean', hits: '310 pkts/s', sev: 'MEDIUM' },
    { country: 'South America / BR', flag: '🇧🇷', ip: '179.185.12.89', asn: 'AS28573 Claro S.A.', hits: '190 pkts/s', sev: 'LOW' },
  ];

  const defaultTargets = [
    { host: 'corp-ad-dc01.internal', ip: '10.240.10.4', role: 'Domain Controller (Kerberos/AD)', risk: 94, status: 'ISOLATED' },
    { host: 'k8s-ingress-proxy.dmz', ip: '10.240.10.12', role: 'API Gateway / Reverse Proxy', risk: 78, status: 'FILTERING' },
    { host: 'db-cust-vault.prod', ip: '10.240.20.88', role: 'Primary PostgreSQL Cluster', risk: 62, status: 'SECURED' },
    { host: 'swift-financial-gw.prod', ip: '10.240.30.5', role: 'Interbank Settlement Bus', risk: 45, status: 'HEALTHY' },
  ];

  const originList = origins || defaultOrigins;
  const targetList = targets || defaultTargets;

  return (
    <div className="glass-card" style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: '#f59e0b' }}>🌐</span> Global Threat Origin & Asset Targeting Radar
          </h3>
          <p style={{ margin: '4px 0 0', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Real-time adversary geographic telemetry correlated with protected internal enterprise crown jewels
          </p>
        </div>
        <span style={{ fontSize: '0.75rem', padding: '4px 10px', borderRadius: 20, background: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b', border: '1px solid rgba(245, 158, 11, 0.3)', fontWeight: 600 }}>
          ⚡ 5 Autonomous Edge Probes Active
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Left: Top Threat Origins */}
        <div>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>📍</span> Top Adversary Sources & ASNs
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {originList.map((item, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                  borderRadius: 8,
                  padding: '8px 12px',
                  fontSize: '0.8rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: '1.2rem' }}>{item.flag}</span>
                  <div>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.82rem' }}>
                      {item.ip}
                    </div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                      {item.country} · {item.asn}
                    </div>
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontWeight: 700, color: item.sev === 'CRITICAL' ? 'var(--sev-critical)' : 'var(--sev-high)', fontSize: '0.8rem' }}>
                    {item.hits}
                  </div>
                  <span style={{ fontSize: '0.65rem', padding: '1px 5px', borderRadius: 3, background: item.sev === 'CRITICAL' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(249, 115, 22, 0.2)', color: item.sev === 'CRITICAL' ? '#ef4444' : '#f97316' }}>
                    {item.sev}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Protected Enterprise Assets */}
        <div>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>🎯</span> Internal Enterprise Targeted Assets
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {targetList.map((item, idx) => (
              <div
                key={idx}
                style={{
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                  borderRadius: 8,
                  padding: '8px 12px',
                  fontSize: '0.8rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                  <span style={{ fontWeight: 700, color: 'var(--accent-cyan)', fontFamily: 'monospace' }}>
                    {item.host}
                  </span>
                  <span
                    style={{
                      fontSize: '0.65rem',
                      padding: '2px 6px',
                      borderRadius: 4,
                      fontWeight: 700,
                      background: item.status === 'ISOLATED' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                      color: item.status === 'ISOLATED' ? '#ef4444' : '#10b981',
                      border: `1px solid ${item.status === 'ISOLATED' ? '#ef444444' : '#10b98144'}`,
                    }}
                  >
                    {item.status}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  <span>{item.ip} · {item.role}</span>
                  <span style={{ color: item.risk > 80 ? 'var(--sev-critical)' : 'var(--accent-cyan)', fontWeight: 600 }}>
                    Risk Index: {item.risk}/100
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
