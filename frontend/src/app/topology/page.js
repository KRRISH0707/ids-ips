'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, Spinner } from '@/components/ui';
import { api } from '@/lib/api';

export default function TopologyPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  const [filter, setFilter] = useState('ALL');

  const fetchTopology = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getNetworkTopology();
      setData(res);
    } catch (err) {
      console.error('Failed to load topology:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTopology();
    const interval = setInterval(fetchTopology, 10000);
    return () => clearInterval(interval);
  }, [fetchTopology]);

  const nodes = data?.nodes || [];
  const edges = data?.edges || [];

  const filteredEdges = edges.filter((e) => {
    if (filter === 'ATTACKS_ONLY') return e.type === 'ATTACK_VECTOR' && e.status !== 'BLOCKED';
    if (filter === 'BLOCKED_ONLY') return e.status === 'BLOCKED';
    return true;
  });

  const getNodeColor = (node) => {
    if (node.status === 'ISOLATED') return '#ef4444';
    if (node.status === 'ATTACKING') return '#f97316';
    if (node.status === 'BLOCKED') return '#6b7280';
    if (node.type === 'GATEWAY') return '#00d4ff';
    if (node.type === 'SENSOR') return '#a855f7';
    if (node.type === 'DATABASE') return '#3b82f6';
    return '#10b981';
  };

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title glow-text">Interactive Network Topology</h1>
          <p className="page-subtitle">Real-time lateral movement mapping, sensor telemetry & containment graph</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            className={`btn btn-sm ${filter === 'ALL' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setFilter('ALL')}
          >
            All Connections
          </button>
          <button
            className={`btn btn-sm ${filter === 'ATTACKS_ONLY' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setFilter('ATTACKS_ONLY')}
          >
            Active Attack Vectors
          </button>
          <button
            className={`btn btn-sm ${filter === 'BLOCKED_ONLY' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setFilter('BLOCKED_ONLY')}
          >
            Blocked / Contained
          </button>
        </div>
      </div>

      {/* KPI Stats Strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 14, marginBottom: 20 }}>
        <div className="glass-card" style={{ padding: '12px 18px', borderLeft: '4px solid var(--accent-cyan)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Monitored Nodes</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, marginTop: 2 }}>{data?.summary?.total_nodes || 0}</div>
        </div>
        <div className="glass-card" style={{ padding: '12px 18px', borderLeft: '4px solid #f97316' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active Vectors</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#fb923c', marginTop: 2 }}>{data?.summary?.total_vectors || 0}</div>
        </div>
        <div className="glass-card" style={{ padding: '12px 18px', borderLeft: '4px solid var(--sev-critical)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Quarantined Hosts</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f87171', marginTop: 2 }}>{data?.summary?.quarantined_nodes || 0}</div>
        </div>
        <div className="glass-card" style={{ padding: '12px 18px', borderLeft: '4px solid #8b5cf6' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Firewall Bans</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#c084fc', marginTop: 2 }}>{data?.summary?.blocked_attackers || 0}</div>
        </div>
      </div>

      {/* Graph Canvas Container */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 320px' : '1fr', gap: 16 }}>
        <div className="glass-card" style={{ position: 'relative', height: 580, overflow: 'hidden', padding: 0 }}>
          {loading && !data ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
              <Spinner />
            </div>
          ) : (
            <svg width="100%" height="100%" viewBox="0 0 900 480" style={{ background: 'radial-gradient(circle at center, #0f172a 0%, #030712 100%)' }}>
              <defs>
                <linearGradient id="laserAttack" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.8" />
                  <stop offset="50%" stopColor="#ff0055" stopOpacity="1" />
                  <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.8" />
                </linearGradient>
                <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="glow" />
                  <feComposite in="SourceGraphic" in2="glow" operator="over" />
                </filter>
              </defs>

              {/* Grid backdrop */}
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
              </pattern>
              <rect width="100%" height="100%" fill="url(#grid)" />

              {/* Edges / Attack Links */}
              {filteredEdges.map((e, idx) => {
                const srcNode = nodes.find((n) => n.id === e.source);
                const tgtNode = nodes.find((n) => n.id === e.target);
                if (!srcNode || !tgtNode) return null;

                const isAttack = e.type === 'ATTACK_VECTOR';
                const isBlocked = e.status === 'BLOCKED';

                return (
                  <g key={idx}>
                    <line
                      x1={srcNode.x}
                      y1={srcNode.y}
                      x2={tgtNode.x}
                      y2={tgtNode.y}
                      stroke={isAttack ? (isBlocked ? '#64748b' : 'url(#laserAttack)') : 'rgba(59, 130, 246, 0.25)'}
                      strokeWidth={isAttack ? 2.5 : 1.2}
                      strokeDasharray={isAttack ? (isBlocked ? '4,4' : '6,4') : 'none'}
                      filter={isAttack && !isBlocked ? 'url(#glow)' : 'none'}
                      style={{
                        animation: isAttack && !isBlocked ? 'dash 1.5s linear infinite' : 'none',
                      }}
                    />
                  </g>
                );
              })}

              {/* Nodes */}
              {nodes.map((node) => {
                const color = getNodeColor(node);
                const isSelected = selectedNode?.id === node.id;
                const isIsolated = node.status === 'ISOLATED';

                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y})`}
                    onClick={() => setSelectedNode(node)}
                    style={{ cursor: 'pointer' }}
                  >
                    {/* Pulsing ring for isolated or attacking nodes */}
                    {(isIsolated || node.status === 'ATTACKING') && (
                      <circle
                        r="24"
                        fill="none"
                        stroke={color}
                        strokeWidth="1.5"
                        opacity="0.6"
                        style={{ animation: 'ping 2s cubic-bezier(0, 0, 0.2, 1) infinite' }}
                      />
                    )}

                    {/* Base Node Circle */}
                    <circle
                      r={node.type === 'GATEWAY' ? 18 : 14}
                      fill="#1e293b"
                      stroke={color}
                      strokeWidth={isSelected ? 3 : 2}
                      filter="url(#glow)"
                    />

                    {/* Center Dot */}
                    <circle r="5" fill={color} />

                    {/* Label */}
                    <text
                      y="28"
                      textAnchor="middle"
                      fill={isSelected ? '#fff' : '#94a3b8'}
                      fontSize="10"
                      fontWeight={isSelected ? 700 : 500}
                      fontFamily="sans-serif"
                    >
                      {node.label}
                    </text>
                    <text
                      y="39"
                      textAnchor="middle"
                      fill="#64748b"
                      fontSize="8"
                      fontFamily="monospace"
                    >
                      {node.ip}
                    </text>
                  </g>
                );
              })}
            </svg>
          )}

          {/* Legend */}
          <div
            style={{
              position: 'absolute',
              bottom: 12,
              left: 14,
              display: 'flex',
              gap: 14,
              background: 'rgba(15, 23, 42, 0.85)',
              padding: '6px 12px',
              borderRadius: 6,
              border: '1px solid rgba(255, 255, 255, 0.1)',
              fontSize: '0.72rem',
            }}
          >
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#00d4ff' }}></span> Gateway
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#a855f7' }}></span> Sensor Probe
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#3b82f6' }}></span> Database / Core
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }}></span> Quarantined Host
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#f97316' }}></span> Attacker
            </span>
          </div>
        </div>

        {/* Node Detail Inspector Drawer */}
        {selectedNode && (
          <div className="glass-card" style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 700 }}>Asset Telemetry</h3>
              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontSize: '0.82rem' }}>
              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase' }}>Node Name</span>
                <div style={{ fontWeight: 700, marginTop: 2 }}>{selectedNode.label}</div>
              </div>

              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase' }}>IP Address</span>
                <div style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)', marginTop: 2 }}>{selectedNode.ip}</div>
              </div>

              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase' }}>Zone / Segment</span>
                <div style={{ marginTop: 2 }}>{selectedNode.zone}</div>
              </div>

              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase' }}>Current State</span>
                <div style={{ marginTop: 2 }}>
                  <span
                    style={{
                      padding: '2px 8px',
                      borderRadius: 4,
                      fontWeight: 700,
                      fontSize: '0.75rem',
                      background: selectedNode.status === 'ISOLATED' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                      color: selectedNode.status === 'ISOLATED' ? '#f87171' : '#34d399',
                      border: `1px solid ${selectedNode.status === 'ISOLATED' ? '#ef4444' : '#10b981'}`,
                    }}
                  >
                    {selectedNode.status}
                  </span>
                </div>
              </div>

              {selectedNode.status === 'ISOLATED' && (
                <div style={{ padding: 10, background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: 6, fontSize: '0.75rem' }}>
                  🛡️ <b>Machine is currently isolated.</b> Ingress and egress network traffic dropped via IPS firewall.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </PageLayout>
  );
}
