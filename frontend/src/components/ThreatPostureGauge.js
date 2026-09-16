'use client';

export default function ThreatPostureGauge({ score = 78, threatLevel = 'ELEVATED RISK', mttc = '1.4s', blockedCount = 4892 }) {
  // Clamp score between 0 and 100
  const clampedScore = Math.max(0, Math.min(100, score));

  // Determine color theme based on score
  const getColor = (s) => {
    if (s >= 80) return { primary: '#ef4444', glow: 'rgba(239, 68, 68, 0.4)', status: 'CRITICAL THREAT' };
    if (s >= 60) return { primary: '#f97316', glow: 'rgba(249, 115, 22, 0.4)', status: 'ELEVATED RISK' };
    if (s >= 35) return { primary: '#f59e0b', glow: 'rgba(245, 158, 11, 0.4)', status: 'GUARDED' };
    return { primary: '#10b981', glow: 'rgba(16, 185, 129, 0.4)', status: 'SECURE' };
  };

  const theme = getColor(clampedScore);
  const strokeDashoffset = 283 - (283 * clampedScore) / 100;

  return (
    <div className="glass-card" style={{ padding: 24, position: 'relative', overflow: 'hidden' }}>
      {/* Background ambient glow */}
      <div style={{
        position: 'absolute',
        top: -40,
        right: -40,
        width: 140,
        height: 140,
        borderRadius: '50%',
        background: `radial-gradient(circle, ${theme.glow} 0%, transparent 70%)`,
        pointerEvents: 'none',
      }} />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
            Enterprise Threat Posture Index
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 800, color: theme.primary, marginTop: 2, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: theme.primary, boxShadow: `0 0 8px ${theme.primary}` }} />
            {threatLevel || theme.status}
          </div>
        </div>
        <div style={{
          padding: '4px 10px',
          borderRadius: 20,
          background: 'rgba(0, 212, 255, 0.08)',
          border: '1px solid rgba(0, 212, 255, 0.25)',
          fontSize: '0.75rem',
          color: 'var(--accent-cyan)',
          fontWeight: 600,
          display: 'flex',
          alignItems: 'center',
          gap: 6
        }}>
          <span className="live-dot" style={{ width: 6, height: 6 }} />
          AI Autonomous Radar
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
        {/* Radial Gauge SVG */}
        <div style={{ position: 'relative', width: 130, height: 130, flexShrink: 0 }}>
          <svg viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
            {/* Background Track */}
            <circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke="rgba(255, 255, 255, 0.06)"
              strokeWidth="9"
            />
            {/* Active Gauge Arc */}
            <circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke={theme.primary}
              strokeWidth="9"
              strokeDasharray="283"
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              style={{
                transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.5s ease',
                filter: `drop-shadow(0 0 6px ${theme.primary})`,
              }}
            />
          </svg>
          {/* Centered Score */}
          <div style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <span style={{ fontSize: '1.8rem', fontWeight: 900, color: '#fff', lineHeight: 1 }}>
              {clampedScore}
            </span>
            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontWeight: 600, marginTop: 2 }}>
              / 100
            </span>
          </div>
        </div>

        {/* Tactical Telemetry Metrics */}
        <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 14px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Mean Time to Contain</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 800, color: 'var(--accent-cyan)', marginTop: 2 }}>
              {mttc}
            </div>
            <div style={{ fontSize: '0.65rem', color: 'var(--accent-green)', marginTop: 2 }}>⚡ 98.6% Sub-second</div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 14px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Quarantine Accuracy</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#a855f7', marginTop: 2 }}>
              99.94%
            </div>
            <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginTop: 2 }}>Zero false positives</div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 14px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Attacks Blocked (24h)</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 800, color: 'var(--sev-critical)', marginTop: 2 }}>
              {Number(blockedCount).toLocaleString()}
            </div>
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2 }}>Automated iptables sync</div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 14px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Kill Chain Break Rate</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 800, color: '#10b981', marginTop: 2 }}>
              100%
            </div>
            <div style={{ fontSize: '0.65rem', color: 'var(--accent-green)', marginTop: 2 }}>Stage 1 & 2 severed</div>
          </div>
        </div>
      </div>
    </div>
  );
}
