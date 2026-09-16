'use client';

import { useState, useEffect } from 'react';

/**
 * AttackResolutionPipeline Component
 * Visualizes the sub-second progression of an attack from detection to autonomous mitigation.
 */
export default function AttackResolutionPipeline({ activeAttack, isResolving = false }) {
  const [currentStep, setCurrentStep] = useState(4); // 1: Ingest, 2: Neural, 3: Quarantine, 4: Sealed

  useEffect(() => {
    if (!isResolving) {
      setCurrentStep(4);
      return;
    }

    // Progress through resolution steps sequentially with high-speed cyber latency
    setCurrentStep(1);
    const t1 = setTimeout(() => setCurrentStep(2), 250);
    const t2 = setTimeout(() => setCurrentStep(3), 550);
    const t3 = setTimeout(() => setCurrentStep(4), 850);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  }, [isResolving, activeAttack?.id]);

  const steps = [
    {
      num: 1,
      name: 'Deep Packet Ingest',
      desc: activeAttack ? `${activeAttack.protocol} :${activeAttack.targetPort}` : 'L3/L4/L7 Stream Parsed',
      badge: currentStep >= 1 ? 'CAPTURED' : 'WAITING',
      color: '#00d4ff',
    },
    {
      num: 2,
      name: 'Neural Threat Scored',
      desc: activeAttack ? `Entropy ${activeAttack.threatScore}/100` : 'Heuristic Engine Active',
      badge: currentStep >= 2 ? 'EVALUATED' : 'STANDBY',
      color: '#f59e0b',
    },
    {
      num: 3,
      name: 'Autonomous IPS Sever',
      desc: activeAttack ? `iptables DROP (${activeAttack.attackerIp})` : 'Kernel Firewall Hook',
      badge: currentStep >= 3 ? 'ISOLATED' : 'QUEUED',
      color: '#ef4444',
    },
    {
      num: 4,
      name: 'Containment Verified',
      desc: activeAttack ? `MTTC: ${activeAttack.mttc} · Sealed` : 'Zero-Trust Maintained',
      badge: currentStep >= 4 ? 'RESOLVED' : 'VERIFYING',
      color: '#10b981',
    },
  ];

  return (
    <div className="glass-card" style={{ padding: '16px 20px', border: '1px solid rgba(0, 212, 255, 0.25)', position: 'relative', overflow: 'hidden' }}>
      {/* Background cyber shimmer bar */}
      <div style={{
        position: 'absolute',
        top: 0, left: 0, right: 0, height: 2,
        background: 'linear-gradient(90deg, #00d4ff 0%, #a855f7 50%, #10b981 100%)',
        boxShadow: '0 0 10px rgba(0, 212, 255, 0.5)'
      }} />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: '0.9rem' }}>🛡️</span>
          <span style={{ fontSize: '0.8rem', fontWeight: 800, letterSpacing: '0.06em', color: 'var(--text-primary)', textTransform: 'uppercase' }}>
            Autonomous Incident Resolution Pipeline
          </span>
          {isResolving && (
            <span style={{ fontSize: '0.68rem', padding: '2px 8px', borderRadius: 4, background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: '1px solid #ef4444', fontWeight: 700 }}>
              ACTIVE MITIGATION IN PROGRESS
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
          <span>Target: <b style={{ color: 'var(--accent-cyan)' }}>{activeAttack?.targetAsset || 'Perimeter Gateway'}</b></span>
          <span>·</span>
          <span>Response: <b style={{ color: '#10b981' }}>{activeAttack?.mttc || '0.82s'}</b></span>
        </div>
      </div>

      {/* Pipeline Stages */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, position: 'relative' }}>
        {steps.map((s, idx) => {
          const isActive = currentStep === s.num;
          const isDone = currentStep > s.num;
          const isPending = currentStep < s.num;

          return (
            <div
              key={s.num}
              style={{
                padding: '10px 12px',
                borderRadius: 8,
                background: isActive
                  ? `${s.color}18`
                  : isDone
                  ? 'rgba(16, 185, 129, 0.06)'
                  : 'rgba(255, 255, 255, 0.02)',
                border: isActive
                  ? `1px solid ${s.color}`
                  : isDone
                  ? '1px solid rgba(16, 185, 129, 0.3)'
                  : '1px solid rgba(255, 255, 255, 0.06)',
                transition: 'all 0.3s ease',
                position: 'relative',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <span style={{ fontSize: '0.72rem', fontWeight: 800, color: isActive ? s.color : isDone ? '#10b981' : 'var(--text-muted)' }}>
                  0{s.num}. {s.name}
                </span>
                <span style={{
                  fontSize: '0.62rem',
                  fontWeight: 700,
                  padding: '1px 5px',
                  borderRadius: 3,
                  background: isDone ? 'rgba(16, 185, 129, 0.2)' : isActive ? `${s.color}33` : 'rgba(255,255,255,0.05)',
                  color: isDone ? '#10b981' : isActive ? s.color : 'var(--text-muted)',
                }}>
                  {isDone ? '✓ DONE' : s.badge}
                </span>
              </div>
              <div style={{ fontSize: '0.68rem', color: isPending ? 'var(--text-dim)' : 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {s.desc}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
