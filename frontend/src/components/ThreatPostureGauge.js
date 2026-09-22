'use client';

import React from 'react';

export default function ThreatPostureGauge({
  score = 78,
  threatLevel = 'ELEVATED RISK',
  mttc = '0.42s',
  blockedCount = 67,
  accuracy = '99.98%',
  killChainBreakRate = '100%',
  inspectionLatency = '12μs',
  activeMitigationMode = 'Autonomous L5',
}) {
  // Clamp score between 0 and 100
  const clampedScore = Math.max(0, Math.min(100, score));

  // Determine color theme based on score
  const getColor = (s) => {
    if (s >= 80) return { primary: '#ef4444', glow: 'rgba(239, 68, 68, 0.45)', badgeBg: 'rgba(239, 68, 68, 0.12)', badgeBorder: 'rgba(239, 68, 68, 0.35)', status: 'CRITICAL POSTURE', defcon: 'DEFCON 1' };
    if (s >= 60) return { primary: '#f97316', glow: 'rgba(249, 115, 22, 0.45)', badgeBg: 'rgba(249, 115, 22, 0.12)', badgeBorder: 'rgba(249, 115, 22, 0.35)', status: 'ELEVATED RISK', defcon: 'DEFCON 2' };
    if (s >= 35) return { primary: '#f59e0b', glow: 'rgba(245, 158, 11, 0.45)', badgeBg: 'rgba(245, 158, 11, 0.12)', badgeBorder: 'rgba(245, 158, 11, 0.35)', status: 'GUARDED', defcon: 'DEFCON 3' };
    return { primary: '#10b981', glow: 'rgba(16, 185, 129, 0.45)', badgeBg: 'rgba(16, 185, 129, 0.12)', badgeBorder: 'rgba(16, 185, 129, 0.35)', status: 'SECURE', defcon: 'DEFCON 4' };
  };

  const theme = getColor(clampedScore);
  const strokeDashoffset = 283 - (283 * clampedScore) / 100;

  // Defensive Vector Readiness Items
  const defenseVectors = [
    { name: 'eBPF / XDP Ingress Filter', value: 99.8, detail: 'Line-rate packet drop active', color: '#00d4ff' },
    { name: 'Autonomous IPS iptables Sync', value: 100, detail: 'Kernel table rules synchronized', color: '#10b981' },
    { name: 'Neural Anomaly Classifier', value: 98.9, detail: 'Bi-LSTM + Isolation Forest ensemble', color: '#8b5cf6' },
    { name: 'Zero-Trust Lateral Isolation', value: 100, detail: 'Microsegmentation active', color: '#10b981' },
  ];

  return (
    <div className="glass-card" style={{ padding: '24px', position: 'relative', overflow: 'hidden', display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Background ambient glow */}
      <div style={{
        position: 'absolute',
        top: -60,
        right: -60,
        width: 220,
        height: 220,
        borderRadius: '50%',
        background: `radial-gradient(circle, ${theme.glow} 0%, transparent 70%)`,
        pointerEvents: 'none',
        zIndex: 0,
      }} />

      {/* Top Header Row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12, zIndex: 1, position: 'relative' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 800, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
              Enterprise Threat Posture Index
            </span>
            <span style={{
              fontSize: '0.65rem',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: 4,
              background: theme.badgeBg,
              border: `1px solid ${theme.badgeBorder}`,
              color: theme.primary,
              letterSpacing: '0.06em',
            }}>
              {theme.defcon}
            </span>
          </div>
          <div style={{ fontSize: '1.25rem', fontWeight: 900, color: theme.primary, marginTop: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{
              width: 10,
              height: 10,
              borderRadius: '50%',
              background: theme.primary,
              boxShadow: `0 0 12px ${theme.primary}`,
              display: 'inline-block',
              animation: 'pulse 2s infinite ease-in-out'
            }} />
            {threatLevel || theme.status}
          </div>
        </div>

        {/* Badges & Radar Mode */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <div style={{
            padding: '5px 12px',
            borderRadius: 20,
            background: 'rgba(139, 92, 246, 0.1)',
            border: '1px solid rgba(139, 92, 246, 0.3)',
            fontSize: '0.72rem',
            color: '#c084fc',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: 6
          }}>
            <span>🛡️</span>
            <span>{activeMitigationMode}</span>
          </div>

          <div style={{
            padding: '5px 12px',
            borderRadius: 20,
            background: 'rgba(0, 212, 255, 0.08)',
            border: '1px solid rgba(0, 212, 255, 0.28)',
            fontSize: '0.72rem',
            color: 'var(--accent-cyan)',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: 6
          }}>
            <span className="live-dot" style={{ width: 6, height: 6 }} />
            <span>AI Autonomous Radar</span>
          </div>
        </div>
      </div>

      {/* Middle Section: Radial Gauge + 6 Tactical Telemetry Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 24, alignItems: 'center', zIndex: 1, position: 'relative' }}>
        {/* Radial Tactical Gauge */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
          <div style={{ position: 'relative', width: 145, height: 145, flexShrink: 0 }}>
            <svg viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
              {/* Outer Radar Ticks */}
              <circle
                cx="50"
                cy="50"
                r="48"
                fill="none"
                stroke="rgba(0, 212, 255, 0.12)"
                strokeWidth="1.5"
                strokeDasharray="2, 6"
              />
              {/* Background Track */}
              <circle
                cx="50"
                cy="50"
                r="40"
                fill="none"
                stroke="rgba(255, 255, 255, 0.06)"
                strokeWidth="8"
              />
              {/* Active Gauge Arc */}
              <circle
                cx="50"
                cy="50"
                r="40"
                fill="none"
                stroke={theme.primary}
                strokeWidth="8"
                strokeDasharray="251"
                strokeDashoffset={251 - (251 * clampedScore) / 100}
                strokeLinecap="round"
                style={{
                  transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.5s ease',
                  filter: `drop-shadow(0 0 8px ${theme.primary})`,
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
              <span style={{ fontSize: '2.1rem', fontWeight: 900, color: '#fff', lineHeight: 1, letterSpacing: '-0.02em' }}>
                {clampedScore}
              </span>
              <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: 700, marginTop: 2 }}>
                / 100
              </span>
            </div>
          </div>
          <div style={{
            fontSize: '0.68rem',
            color: 'var(--text-muted)',
            fontWeight: 600,
            textAlign: 'center',
            fontFamily: 'var(--font-mono, monospace)'
          }}>
            SECURITY INDEX
          </div>
        </div>

        {/* 6 Tactical Telemetry Cards Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10 }}>
          <div style={{ background: 'rgba(255, 255, 255, 0.025)', padding: '12px 14px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)', transition: 'all 0.2s ease' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Mean Time to Contain</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 900, color: 'var(--accent-cyan)', marginTop: 2, fontFamily: 'var(--font-mono, monospace)' }}>
              {mttc}
            </div>
            <div style={{ fontSize: '0.67rem', color: 'var(--accent-green)', marginTop: 2, display: 'flex', alignItems: 'center', gap: 4 }}>
              <span>⚡</span> <span>98.6% Sub-second</span>
            </div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.025)', padding: '12px 14px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)', transition: 'all 0.2s ease' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Quarantine Accuracy</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 900, color: '#c084fc', marginTop: 2, fontFamily: 'var(--font-mono, monospace)' }}>
              {accuracy}
            </div>
            <div style={{ fontSize: '0.67rem', color: 'var(--text-secondary)', marginTop: 2 }}>
              Zero false positives
            </div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.025)', padding: '12px 14px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)', transition: 'all 0.2s ease' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Attacks Blocked (24h)</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 900, color: 'var(--sev-critical)', marginTop: 2, fontFamily: 'var(--font-mono, monospace)' }}>
              {Number(blockedCount).toLocaleString()}
            </div>
            <div style={{ fontSize: '0.67rem', color: 'var(--text-muted)', marginTop: 2 }}>
              Automated iptables sync
            </div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.025)', padding: '12px 14px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)', transition: 'all 0.2s ease' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Kill Chain Break Rate</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 900, color: '#10b981', marginTop: 2, fontFamily: 'var(--font-mono, monospace)' }}>
              {killChainBreakRate}
            </div>
            <div style={{ fontSize: '0.67rem', color: 'var(--accent-green)', marginTop: 2 }}>
              Stage 1 & 2 severed
            </div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.025)', padding: '12px 14px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)', transition: 'all 0.2s ease' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Inspection Latency</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 900, color: '#38bdf8', marginTop: 2, fontFamily: 'var(--font-mono, monospace)' }}>
              {inspectionLatency}
            </div>
            <div style={{ fontSize: '0.67rem', color: 'var(--text-secondary)', marginTop: 2 }}>
              Hardware eBPF offloaded
            </div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.025)', padding: '12px 14px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)', transition: 'all 0.2s ease' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>Perimeter Containment</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 900, color: '#10b981', marginTop: 2, fontFamily: 'var(--font-mono, monospace)' }}>
              100%
            </div>
            <div style={{ fontSize: '0.67rem', color: 'var(--accent-green)', marginTop: 2 }}>
              0 Escaped Incidents
            </div>
          </div>
        </div>
      </div>

      {/* Defense Vector Surface Health Breakdown */}
      <div style={{
        background: 'rgba(6, 13, 26, 0.65)',
        border: '1px solid rgba(0, 212, 255, 0.12)',
        borderRadius: 12,
        padding: '14px 16px',
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
        zIndex: 1,
        position: 'relative'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Defensive Vector Surface Readiness
          </span>
          <span style={{ fontSize: '0.7rem', color: 'var(--accent-green)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
            <span>●</span> All Vectors Hermetic
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
          {defenseVectors.map((vec, i) => (
            <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.72rem' }}>
                <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{vec.name}</span>
                <span style={{ color: vec.color, fontWeight: 700, fontFamily: 'var(--font-mono, monospace)' }}>{vec.value}%</span>
              </div>
              <div style={{ width: '100%', height: 4, background: 'rgba(255, 255, 255, 0.08)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{
                  width: `${vec.value}%`,
                  height: '100%',
                  background: `linear-gradient(90deg, ${vec.color}, #00d4ff)`,
                  borderRadius: 2,
                  boxShadow: `0 0 6px ${vec.color}`,
                  transition: 'width 0.8s ease'
                }} />
              </div>
              <span style={{ fontSize: '0.64rem', color: 'var(--text-muted)' }}>{vec.detail}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Cyber Telemetry Status Ribbon Footer */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12,
        paddingTop: 12,
        borderTop: '1px solid rgba(255, 255, 255, 0.06)',
        fontSize: '0.7rem',
        color: 'var(--text-muted)',
        zIndex: 1,
        position: 'relative'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ color: 'var(--accent-cyan)' }}>🛡️</span>
          <span>eBPF Kernel Probes:</span>
          <span style={{ color: '#10b981', fontWeight: 700 }}>SYNCHRONIZED (4/4 NODES)</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ color: 'var(--accent-cyan)' }}>⚡</span>
          <span>Automated IPS Dispatch:</span>
          <span style={{ color: '#00d4ff', fontWeight: 700 }}>ACTIVE (&lt; 50ms)</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ color: 'var(--accent-cyan)' }}>🔒</span>
          <span>Quarantined Edge IPs:</span>
          <span style={{ color: 'var(--sev-critical)', fontWeight: 700 }}>{Number(blockedCount).toLocaleString()} ACTIVE BLOCKS</span>
        </div>
      </div>
    </div>
  );
}

