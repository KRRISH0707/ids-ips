'use client';

import { useState, useEffect } from 'react';

export default function GeoThreatRadar({ origins = null, targets = null }) {
  const defaultOrigins = [
    { country: 'Eastern Europe / RU', flag: '🇷🇺', ip: '185.220.101.5', asn: 'AS9009 Tor Exit', hits: '1,420 pkts/s', sev: 'CRITICAL', angle: 45, radius: 65 },
    { country: 'East Asia / CN', flag: '🇨🇳', ip: '45.33.32.156', asn: 'AS4134 Chinanet', hits: '980 pkts/s', sev: 'HIGH', angle: 135, radius: 75 },
    { country: 'Western Europe / NL', flag: '🇳🇱', ip: '198.51.100.42', asn: 'AS16276 OVH SAS', hits: '520 pkts/s', sev: 'MEDIUM', angle: 215, radius: 55 },
    { country: 'North America / US', flag: '🇺🇸', ip: '203.0.113.15', asn: 'AS14061 DigitalOcean', hits: '310 pkts/s', sev: 'MEDIUM', angle: 300, radius: 40 },
    { country: 'South America / BR', flag: '🇧🇷', ip: '179.185.12.89', asn: 'AS28573 Claro S.A.', hits: '190 pkts/s', sev: 'LOW', angle: 170, radius: 85 },
  ];

  const defaultTargets = [
    { host: 'corp-ad-dc01.internal', ip: '10.240.10.4', role: 'Domain Controller (Kerberos/AD)', risk: 94, status: 'ISOLATED' },
    { host: 'k8s-ingress-proxy.dmz', ip: '10.240.10.12', role: 'API Gateway / Reverse Proxy', risk: 78, status: 'FILTERING' },
    { host: 'db-cust-vault.prod', ip: '10.240.20.88', role: 'Primary PostgreSQL Cluster', risk: 62, status: 'SECURED' },
    { host: 'swift-financial-gw.prod', ip: '10.240.30.5', role: 'Interbank Settlement Bus', risk: 45, status: 'HEALTHY' },
  ];

  const originList = origins || defaultOrigins;
  const targetList = targets || defaultTargets;

  const [activeBlip, setActiveBlip] = useState(0);
  const [activeTab, setActiveTab] = useState('all'); // 'all' | 'origins' | 'targets'

  useEffect(() => {
    const timer = setInterval(() => {
      setActiveBlip((prev) => (prev + 1) % originList.length);
    }, 2500);
    return () => clearInterval(timer);
  }, [originList.length]);

  return (
    <div
      className="glass-card geo-radar-card"
      data-horizontal-scroll="true"
      style={{
        padding: 24,
        position: 'relative',
        overflow: 'visible',
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 18 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ flex: '1 1 280px', minWidth: 280 }}>
            <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 800, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: '#f59e0b' }}>🌐</span> Global Threat Origin & Enterprise Target Radar
            </h3>
            <p style={{ margin: '4px 0 0', fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.45, maxWidth: '100%' }}>
              Real-time adversary geographic telemetry correlated with protected internal enterprise crown jewels
            </p>
          </div>

          <span style={{ fontSize: '0.72rem', padding: '4px 10px', borderRadius: 20, background: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b', border: '1px solid rgba(245, 158, 11, 0.3)', fontWeight: 600, whiteSpace: 'nowrap' }}>
            ⚡ 5 Edge Probes Active
          </span>
        </div>

        {/* Quick Filter Pill Buttons Row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Filter Feeds:
          </span>
          <div style={{ display: 'inline-flex', background: 'rgba(255,255,255,0.04)', borderRadius: 16, padding: 2, border: '1px solid rgba(255,255,255,0.08)' }}>
            <button
              onClick={() => setActiveTab('all')}
              style={{
                border: 'none',
                background: activeTab === 'all' ? 'linear-gradient(135deg, rgba(0, 212, 255, 0.25), rgba(59, 130, 246, 0.3))' : 'transparent',
                color: activeTab === 'all' ? '#ffffff' : 'var(--text-secondary)',
                fontSize: '0.72rem',
                fontWeight: activeTab === 'all' ? 700 : 500,
                padding: '3px 10px',
                borderRadius: 14,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              All Columns
            </button>
            <button
              onClick={() => setActiveTab('origins')}
              style={{
                border: 'none',
                background: activeTab === 'origins' ? 'linear-gradient(135deg, rgba(0, 212, 255, 0.25), rgba(59, 130, 246, 0.3))' : 'transparent',
                color: activeTab === 'origins' ? '#ffffff' : 'var(--text-secondary)',
                fontSize: '0.72rem',
                fontWeight: activeTab === 'origins' ? 700 : 500,
                padding: '3px 10px',
                borderRadius: 14,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              Adversaries ({originList.length})
            </button>
            <button
              onClick={() => setActiveTab('targets')}
              style={{
                border: 'none',
                background: activeTab === 'targets' ? 'linear-gradient(135deg, rgba(0, 212, 255, 0.25), rgba(59, 130, 246, 0.3))' : 'transparent',
                color: activeTab === 'targets' ? '#ffffff' : 'var(--text-secondary)',
                fontSize: '0.72rem',
                fontWeight: activeTab === 'targets' ? 700 : 500,
                padding: '3px 10px',
                borderRadius: 14,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              Crown Jewels ({targetList.length})
            </button>
          </div>
        </div>
      </div>

      {/* Grid container with adaptive responsive styling */}
      <div className={`geo-radar-grid view-${activeTab}`}>
        {/* Radar Graphic Viewport */}
        <div
          className="geo-radar-sweep-col"
          style={{
            background: 'rgba(2, 6, 12, 0.8)',
            border: '1px solid rgba(0, 212, 255, 0.2)',
            borderRadius: 14,
            padding: 16,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            position: 'relative',
            boxShadow: 'inset 0 0 20px rgba(0,212,255,0.05)',
            minWidth: 0,
          }}
        >
          <div style={{ fontSize: '0.68rem', fontWeight: 800, color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10, textAlign: 'center' }}>
            📡 TACTICAL RADAR SWEEP
          </div>

          <div style={{ position: 'relative', width: 170, height: 170, flexShrink: 0 }}>
            {/* Radar Grid Circles */}
            <svg viewBox="0 0 200 200" style={{ width: '100%', height: '100%', overflow: 'visible' }}>
              <defs>
                <radialGradient id="radarGlow" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="rgba(0,212,255,0.15)" />
                  <stop offset="100%" stopColor="rgba(0,212,255,0)" />
                </radialGradient>
              </defs>
              <circle cx="100" cy="100" r="95" fill="url(#radarGlow)" stroke="rgba(0,212,255,0.25)" strokeWidth="1" strokeDasharray="3 3" />
              <circle cx="100" cy="100" r="70" fill="none" stroke="rgba(0,212,255,0.2)" strokeWidth="1" />
              <circle cx="100" cy="100" r="45" fill="none" stroke="rgba(0,212,255,0.15)" strokeWidth="1" />
              <circle cx="100" cy="100" r="20" fill="none" stroke="rgba(0,212,255,0.1)" strokeWidth="1" />

              {/* Crosshairs */}
              <line x1="100" y1="5" x2="100" y2="195" stroke="rgba(0,212,255,0.15)" strokeWidth="1" />
              <line x1="5" y1="100" x2="195" y2="100" stroke="rgba(0,212,255,0.15)" strokeWidth="1" />

              {/* Rotating Sweep Line */}
              <g style={{ transformOrigin: '100px 100px', animation: 'spin 4s linear infinite' }}>
                <line x1="100" y1="100" x2="100" y2="5" stroke="var(--accent-cyan)" strokeWidth="2" opacity="0.8" />
                <polygon points="100,100 100,5 140,25" fill="rgba(0, 212, 255, 0.15)" />
              </g>

              {/* Plot Blips */}
              {originList.map((item, idx) => {
                const angleRad = ((item.angle || idx * 72) - 90) * (Math.PI / 180);
                const r = (item.radius || 60) * 0.9;
                const cx = 100 + r * Math.cos(angleRad);
                const cy = 100 + r * Math.sin(angleRad);
                const isSelected = activeBlip === idx;
                const color = item.sev === 'CRITICAL' ? '#ef4444' : item.sev === 'HIGH' ? '#f97316' : '#f59e0b';

                return (
                  <g key={idx} style={{ cursor: 'pointer' }} onClick={() => setActiveBlip(idx)}>
                    {isSelected && (
                      <circle cx={cx} cy={cy} r="12" fill="none" stroke={color} strokeWidth="1.5" opacity="0.6">
                        <animate attributeName="r" values="6;16;6" dur="1.5s" repeatCount="indefinite" />
                        <animate attributeName="opacity" values="0.8;0.1;0.8" dur="1.5s" repeatCount="indefinite" />
                      </circle>
                    )}
                    <circle cx={cx} cy={cy} r="4" fill={color} filter={`drop-shadow(0 0 4px ${color})`} />
                  </g>
                );
              })}

              {/* Central Protected Core */}
              <circle cx="100" cy="100" r="5" fill="#10b981" />
            </svg>
          </div>

          <div style={{ marginTop: 10, textAlign: 'center', fontSize: '0.72rem', color: 'var(--text-secondary)', width: '100%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            Target Lock: <b style={{ color: originList[activeBlip]?.sev === 'CRITICAL' ? '#ef4444' : '#f59e0b' }}>
              {originList[activeBlip]?.flag} {originList[activeBlip]?.ip}
            </b>
          </div>
        </div>

        {/* Middle: Top Threat Origins */}
        {(activeTab === 'all' || activeTab === 'origins') && (
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 10, display: 'flex', alignItems: 'center', justifyContent: 'space-between', letterSpacing: '0.04em' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span>📍</span> Adversary Sources & Ingress ASNs
              </span>
              <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>{originList.length} nodes</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {originList.map((item, idx) => {
                const isSelected = activeBlip === idx;
                return (
                  <div
                    key={idx}
                    onClick={() => setActiveBlip(idx)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      background: isSelected ? 'rgba(0, 212, 255, 0.08)' : 'rgba(255, 255, 255, 0.02)',
                      border: `1px solid ${isSelected ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.06)'}`,
                      borderRadius: 8,
                      padding: '7px 10px',
                      fontSize: '0.78rem',
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                      gap: 8,
                      minWidth: 0,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, flex: 1 }}>
                      <span style={{ fontSize: '1.1rem', flexShrink: 0 }}>{item.flag}</span>
                      <div style={{ minWidth: 0, overflow: 'hidden' }}>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.8rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={item.ip}>
                          {item.ip}
                        </div>
                        <div style={{ fontSize: '0.67rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={`${item.country} · ${item.asn}`}>
                          {item.country} · {item.asn}
                        </div>
                      </div>
                    </div>
                    <div style={{ textAlign: 'right', flexShrink: 0 }}>
                      <div style={{ fontWeight: 700, color: item.sev === 'CRITICAL' ? 'var(--sev-critical)' : 'var(--sev-high)', fontSize: '0.75rem' }}>
                        {item.hits}
                      </div>
                      <span style={{ fontSize: '0.62rem', padding: '1px 5px', borderRadius: 3, background: item.sev === 'CRITICAL' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(249, 115, 22, 0.2)', color: item.sev === 'CRITICAL' ? '#ef4444' : '#f97316', fontWeight: 700 }}>
                        {item.sev}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Right: Protected Enterprise Assets / Crown Jewels */}
        {(activeTab === 'all' || activeTab === 'targets') && (
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 10, display: 'flex', alignItems: 'center', justifyContent: 'space-between', letterSpacing: '0.04em' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span>🎯</span> Internal Targeted Crown Jewels
              </span>
              <span style={{ fontSize: '0.68rem', color: '#10b981', fontWeight: 600 }}>Active Defense</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {targetList.map((item, idx) => (
                <div
                  key={idx}
                  style={{
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                    borderRadius: 8,
                    padding: '7px 10px',
                    fontSize: '0.78rem',
                    minWidth: 0,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3, gap: 8 }}>
                    <span style={{ fontWeight: 700, color: 'var(--accent-cyan)', fontFamily: 'monospace', fontSize: '0.78rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }} title={item.host}>
                      {item.host}
                    </span>
                    <span
                      style={{
                        fontSize: '0.62rem',
                        padding: '1px 5px',
                        borderRadius: 4,
                        fontWeight: 700,
                        background: item.status === 'ISOLATED' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                        color: item.status === 'ISOLATED' ? '#ef4444' : '#10b981',
                        border: `1px solid ${item.status === 'ISOLATED' ? '#ef444444' : '#10b98144'}`,
                        flexShrink: 0,
                      }}
                    >
                      {item.status}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.67rem', color: 'var(--text-muted)', gap: 6 }}>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }} title={`${item.ip} · ${item.role}`}>
                      {item.ip} · {item.role}
                    </span>
                    <span style={{ color: item.risk > 80 ? 'var(--sev-critical)' : 'var(--accent-cyan)', fontWeight: 700, flexShrink: 0 }}>
                      Risk {item.risk}/100
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
