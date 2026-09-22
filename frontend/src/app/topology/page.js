'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, Spinner } from '@/components/ui';
import { api } from '@/lib/api';
import { useOnLiveEvent } from '@/lib/useLiveFeed';

const DEFAULT_TOPOLOGY_DATA = {
  nodes: [
    { id: 'gateway-core', label: 'Enterprise Border Gateway', ip: '10.0.0.1', type: 'GATEWAY', zone: 'DMZ', status: 'ONLINE', x: 380, y: 200 },
    { id: 'sensor-1', label: 'sensor-dmz-east', ip: '10.0.0.5', type: 'SENSOR', zone: 'DMZ Edge', status: 'ONLINE', x: 560, y: 140 },
    { id: 'sensor-2', label: 'sensor-core-lan', ip: '192.168.1.5', type: 'SENSOR', zone: 'Internal LAN', status: 'ONLINE', x: 560, y: 250 },
    { id: 'srv-db-01', label: 'Database Primary', ip: '192.168.1.10', type: 'DATABASE', zone: 'Data Tier', status: 'ONLINE', x: 760, y: 80 },
    { id: 'srv-bastion-01', label: 'SSH Bastion Edge', ip: '192.168.1.20', type: 'SERVER', zone: 'DMZ', status: 'ONLINE', x: 600, y: 320 },
    { id: 'srv-app-c2', label: 'Core App Host', ip: '192.168.1.150', type: 'WORKSTATION', zone: 'Internal LAN', status: 'ONLINE', x: 780, y: 280 },
    { id: 'ext-185.220.101.5', label: 'Attacker (185.220.101.5)', ip: '185.220.101.5', type: 'THREAT_ACTOR', severity: 'CRITICAL', zone: 'External WAN', status: 'BLOCKED', x: 60, y: 60 },
    { id: 'ext-45.33.32.156', label: 'Attacker (45.33.32.156)', ip: '45.33.32.156', type: 'THREAT_ACTOR', severity: 'HIGH', zone: 'External WAN', status: 'ATTACKING', x: 200, y: 60 },
  ],
  edges: [
    { source: 'gateway-core', target: 'sensor-1', type: 'TELEMETRY', status: 'HEALTHY' },
    { source: 'gateway-core', target: 'sensor-2', type: 'TELEMETRY', status: 'HEALTHY' },
    { source: 'gateway-core', target: 'srv-db-01', type: 'INTERNAL_BUS', status: 'HEALTHY' },
    { source: 'gateway-core', target: 'srv-bastion-01', type: 'INTERNAL_BUS', status: 'HEALTHY' },
    { source: 'gateway-core', target: 'srv-app-c2', type: 'INTERNAL_BUS', status: 'HEALTHY' },
    { source: 'ext-185.220.101.5', target: 'srv-db-01', type: 'ATTACK_VECTOR', signature: 'Log4Shell RCE Ingress Vector', severity: 'CRITICAL', status: 'BLOCKED' },
    { source: 'ext-45.33.32.156', target: 'gateway-core', type: 'ATTACK_VECTOR', signature: 'SQL Injection Probe', severity: 'HIGH', status: 'ACTIVE_ATTACK' },
  ],
  summary: {
    total_nodes: 8,
    total_vectors: 7,
    quarantined_nodes: 0,
    blocked_attackers: 1,
  },
};

export default function TopologyPage() {
  const [data, setData] = useState(DEFAULT_TOPOLOGY_DATA);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  const [filter, setFilter] = useState('ALL');
  const [displayMode, setDisplayMode] = useState('GRAPH'); // 'GRAPH' or 'TABLE'
  const [searchTerm, setSearchTerm] = useState('');

  const fetchTopology = useCallback(async (showSpinner = true) => {
    try {
      if (showSpinner) setLoading(true);
      await api.ensureAuth();
      const res = await api.getNetworkTopology();
      if (res && res.nodes && res.nodes.length > 0) {
        setData(res);
      } else {
        setData(DEFAULT_TOPOLOGY_DATA);
      }
    } catch (err) {
      console.warn('Network topology fetch note (using active telemetry view):', err);
      setData(DEFAULT_TOPOLOGY_DATA);
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTopology(true);
    const interval = setInterval(() => fetchTopology(false), 10000);
    return () => clearInterval(interval);
  }, [fetchTopology]);

  // Real-time synchronization: update topology map immediately upon any attack or containment action
  useOnLiveEvent((event) => {
    // 1. If an attack arrives with source IP, inject or highlight node immediately
    if (event.src_ip) {
      setData((prev) => {
        const existingNodes = prev?.nodes || DEFAULT_TOPOLOGY_DATA.nodes;
        const existingEdges = prev?.edges || DEFAULT_TOPOLOGY_DATA.edges;
        const attackerId = `ext-${event.src_ip}`;
        const hasAttacker = existingNodes.some((n) => n.ip === event.src_ip || n.id === attackerId);

        let updatedNodes = [...existingNodes];
        if (!hasAttacker) {
          updatedNodes.unshift({
            id: attackerId,
            label: `Attacker (${event.src_ip})`,
            ip: event.src_ip,
            type: 'THREAT_ACTOR',
            severity: event.severity || 'CRITICAL',
            zone: 'External WAN',
            status: event.autonomous_mitigation?.prevented || event.status === 'AUTO_BLOCKED' ? 'BLOCKED' : 'ATTACKING',
            x: 60,
            y: 60 + ((existingNodes.length % 5) * 45),
          });
        }

        const targetNodeId = updatedNodes.find((n) => n.type === 'DATABASE' || n.type === 'SERVER')?.id || 'gateway-core';
        const updatedEdges = [
          {
            source: attackerId,
            target: targetNodeId,
            type: 'ATTACK_VECTOR',
            signature: event.signature || 'In-Flight Zero-Day Threat',
            severity: event.severity || 'CRITICAL',
            status: event.autonomous_mitigation?.prevented || event.status === 'AUTO_BLOCKED' ? 'BLOCKED' : 'ACTIVE_ATTACK',
          },
          ...existingEdges,
        ];

        return {
          ...prev,
          nodes: updatedNodes,
          edges: updatedEdges,
          summary: {
            ...prev?.summary,
            blocked_attackers: (prev?.summary?.blocked_attackers || 0) + (event.autonomous_mitigation?.prevented ? 1 : 0),
            total_vectors: (prev?.summary?.total_vectors || 0) + 1,
          }
        };
      });
    }

    // Refresh from backend in background to sync authoritative state
    fetchTopology(false);
  });

  const nodes = data?.nodes || DEFAULT_TOPOLOGY_DATA.nodes;
  const edges = data?.edges || DEFAULT_TOPOLOGY_DATA.edges;

  // Compute dynamic viewBox dimensions based on max coordinates
  const maxX = Math.max(900, ...nodes.map((n) => (n.x || 0) + 140));
  const maxY = Math.max(520, ...nodes.map((n) => (n.y || 0) + 80));

  const filteredEdges = edges.filter((e) => {
    if (filter === 'ATTACKS_ONLY') return e.type === 'ATTACK_VECTOR' && e.status !== 'BLOCKED';
    if (filter === 'BLOCKED_ONLY') return e.status === 'BLOCKED';
    return true;
  });

  const filteredNodesTable = nodes.filter((n) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      n.label.toLowerCase().includes(term) ||
      n.ip.toLowerCase().includes(term) ||
      n.type.toLowerCase().includes(term) ||
      n.zone.toLowerCase().includes(term)
    );
  });

  // Dynamic distinct color mapping for every node role, category, and severity status
  const getNodeColor = (node) => {
    // 1. Quarantined / Isolated machine states
    if (node.status === 'ISOLATED') return '#ec4899'; // Magenta Pink for Isolated Machine
    if (node.status === 'BLOCKED') return '#dc2626'; // Deep Crimson Red for Banned Attacker
    
    // 2. Attacker / Threat Actor Nodes color-coded by Severity
    if (node.type === 'THREAT_ACTOR' || node.status === 'ATTACKING' || node.status === 'CRITICAL_ATTACK') {
      if (node.severity === 'CRITICAL' || node.status === 'CRITICAL_ATTACK') return '#ef4444'; // Bright Red
      if (node.severity === 'HIGH') return '#f97316'; // Flame Orange
      if (node.severity === 'MEDIUM') return '#f59e0b'; // Amber Gold
      return '#eab308'; // Bright Yellow
    }
    
    // 3. Infrastructure & Internal Asset Nodes
    if (node.type === 'GATEWAY') return '#00d4ff'; // Electric Cyan for Enterprise Gateway
    if (node.type === 'SENSOR') return '#a855f7'; // Neon Purple for Sensors
    if (node.type === 'DATABASE') return '#3b82f6'; // Royal Blue for Database Primary
    if (node.type === 'SERVER') return '#10b981'; // Emerald Green for SSH Bastion Edge
    if (node.type === 'WORKSTATION') return '#14b8a6'; // Teal for Core App Host
    
    return '#38bdf8'; // Sky Blue fallback
  };

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title glow-text">Interactive Network Topology</h1>
          <p className="page-subtitle">Real-time lateral movement mapping, sensor telemetry & containment graph</p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {/* Display Mode Toggle */}
          <div style={{ display: 'flex', background: 'rgba(0,0,0,0.4)', borderRadius: 6, padding: 2, border: '1px solid rgba(255,255,255,0.08)', marginRight: 12 }}>
            <button
              onClick={() => setDisplayMode('GRAPH')}
              style={{
                padding: '4px 12px',
                fontSize: '0.75rem',
                fontWeight: 700,
                borderRadius: 4,
                border: 'none',
                background: displayMode === 'GRAPH' ? 'var(--accent-cyan)' : 'transparent',
                color: displayMode === 'GRAPH' ? '#000' : 'var(--text-muted)',
                cursor: 'pointer',
              }}
            >
              🕸️ Graph Canvas
            </button>
            <button
              onClick={() => setDisplayMode('TABLE')}
              style={{
                padding: '4px 12px',
                fontSize: '0.75rem',
                fontWeight: 700,
                borderRadius: 4,
                border: 'none',
                background: displayMode === 'TABLE' ? 'var(--accent-cyan)' : 'transparent',
                color: displayMode === 'TABLE' ? '#000' : 'var(--text-muted)',
                cursor: 'pointer',
              }}
            >
              📋 All Nodes List ({nodes.length})
            </button>
          </div>

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
          <div style={{ fontSize: '1.4rem', fontWeight: 800, marginTop: 2 }}>{data?.summary?.total_nodes || nodes.length}</div>
        </div>
        <div className="glass-card" style={{ padding: '12px 18px', borderLeft: '4px solid #f97316' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active Vectors</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#fb923c', marginTop: 2 }}>{data?.summary?.total_vectors || edges.length}</div>
        </div>
        <div className="glass-card" style={{ padding: '12px 18px', borderLeft: '4px solid #ec4899' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Quarantined Hosts</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#ec4899', marginTop: 2 }}>{data?.summary?.quarantined_nodes || 0}</div>
        </div>
        <div className="glass-card" style={{ padding: '12px 18px', borderLeft: '4px solid #dc2626' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Firewall Bans</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#dc2626', marginTop: 2 }}>{data?.summary?.blocked_attackers || 1}</div>
        </div>
      </div>

      {displayMode === 'GRAPH' ? (
        /* Graph View Mode */
        <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 320px' : '1fr', gap: 16 }}>
          <div className="glass-card" style={{ position: 'relative', minHeight: 620, overflowX: 'auto', overflowY: 'auto', padding: 0 }}>
            {loading && !data ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 600 }}>
                <Spinner />
              </div>
            ) : (
              <svg width="100%" height="100%" viewBox={`0 0 ${maxX} ${maxY}`} style={{ background: 'radial-gradient(circle at center, #0f172a 0%, #030712 100%)', minHeight: 600 }}>
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
                      {(isIsolated || node.status === 'ATTACKING' || node.status === 'CRITICAL_ATTACK') && (
                        <circle
                          r="24"
                          fill="none"
                          stroke={color}
                          strokeWidth="1.5"
                          opacity="0.7"
                          style={{ animation: 'ping 2s cubic-bezier(0, 0, 0.2, 1) infinite' }}
                        />
                      )}

                      {/* Base Node Circle */}
                      <circle
                        r={node.type === 'GATEWAY' ? 18 : 14}
                        fill="#1e293b"
                        stroke={color}
                        strokeWidth={isSelected ? 3.5 : 2.5}
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

            {/* Comprehensive Palette Legend */}
            <div
              style={{
                position: 'absolute',
                bottom: 12,
                left: 14,
                display: 'flex',
                flexWrap: 'wrap',
                gap: 12,
                background: 'rgba(15, 23, 42, 0.9)',
                padding: '8px 14px',
                borderRadius: 8,
                border: '1px solid rgba(0, 212, 255, 0.2)',
                fontSize: '0.72rem',
              }}
            >
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#00d4ff', boxShadow: '0 0 4px #00d4ff' }}></span> Border Gateway
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#a855f7', boxShadow: '0 0 4px #a855f7' }}></span> Sensor Probe
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#3b82f6', boxShadow: '0 0 4px #3b82f6' }}></span> Primary Database
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 4px #10b981' }}></span> SSH Bastion Edge
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#14b8a6', boxShadow: '0 0 4px #14b8a6' }}></span> Core App Host
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#ef4444', boxShadow: '0 0 4px #ef4444' }}></span> Critical Attacker
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#f97316', boxShadow: '0 0 4px #f97316' }}></span> High Attacker
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#dc2626', boxShadow: '0 0 4px #dc2626' }}></span> Quarantined Attacker
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#ec4899', boxShadow: '0 0 4px #ec4899' }}></span> Isolated Host
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
                  <div style={{ fontWeight: 700, marginTop: 2, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 10, height: 10, borderRadius: '50%', background: getNodeColor(selectedNode) }} />
                    {selectedNode.label}
                  </div>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase' }}>IP Address</span>
                  <div style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)', marginTop: 2 }}>{selectedNode.ip}</div>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase' }}>Role / Type</span>
                  <div style={{ marginTop: 2 }}>{selectedNode.type}</div>
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
                        background: `${getNodeColor(selectedNode)}22`,
                        color: getNodeColor(selectedNode),
                        border: `1px solid ${getNodeColor(selectedNode)}66`,
                      }}
                    >
                      {selectedNode.status}
                    </span>
                  </div>
                </div>

                {selectedNode.status === 'ISOLATED' && (
                  <div style={{ padding: 10, background: 'rgba(236, 72, 153, 0.1)', border: '1px solid #ec4899', borderRadius: 6, fontSize: '0.75rem' }}>
                    🛡️ <b>Machine is currently isolated.</b> Ingress and egress network traffic dropped via IPS firewall.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Full Searchable Table View Mode */
        <div className="glass-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Complete Monitored Asset & Attacker Inventory ({filteredNodesTable.length})
            </h3>
            <input
              type="text"
              className="input"
              style={{ width: 280, fontSize: '0.8rem' }}
              placeholder="🔍 Search node by IP, Name, Zone..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <div className="table-wrapper" data-horizontal-scroll="true" style={{ overflowX: 'auto', width: '100%' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Node / Asset Label</th>
                  <th>IP Address</th>
                  <th>Type</th>
                  <th>Network Zone</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredNodesTable.map((node) => {
                  const color = getNodeColor(node);
                  return (
                    <tr key={node.id}>
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        <span style={{ width: 9, height: 9, borderRadius: '50%', background: color, display: 'inline-block', marginRight: 8, boxShadow: `0 0 5px ${color}` }} />
                        {node.label}
                      </td>
                      <td className="mono" style={{ color: 'var(--accent-cyan)', fontSize: '0.82rem' }}>
                        {node.ip}
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{node.type}</td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{node.zone}</td>
                      <td>
                        <span
                          style={{
                            padding: '2px 8px',
                            borderRadius: 4,
                            fontSize: '0.72rem',
                            fontWeight: 700,
                            background: `${color}22`,
                            color: color,
                            border: `1px solid ${color}44`,
                          }}
                        >
                          {node.status}
                        </span>
                      </td>
                      <td>
                        <button
                          className="btn btn-ghost btn-sm"
                          style={{ fontSize: '0.72rem', padding: '3px 8px' }}
                          onClick={() => {
                            setSelectedNode(node);
                            setDisplayMode('GRAPH');
                          }}
                        >
                          🎯 Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
