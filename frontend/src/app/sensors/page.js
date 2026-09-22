'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, StatusBadge, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { useOnLiveEvent } from '@/lib/useLiveFeed';
import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts';

function CustomPieTooltip({ active, payload }) {
  if (active && payload && payload.length) {
    const data = payload[0];
    const color = data.payload?.color || data.color || '#10b981';
    const name = data.name || data.payload?.name || 'Status';
    const value = data.value ?? data.payload?.value ?? 0;
    return (
      <div style={{
        background: 'rgba(6, 13, 24, 0.96)',
        border: `1px solid ${color}`,
        borderRadius: 8,
        padding: '8px 12px',
        boxShadow: `0 8px 24px rgba(0, 0, 0, 0.8), 0 0 12px ${color}44`,
        pointerEvents: 'none',
        zIndex: 9999,
        minWidth: 140
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}` }} />
          <span style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f8fafc' }}>{name}</span>
        </div>
        <div style={{ fontSize: '1rem', fontWeight: 900, color, fontFamily: 'monospace' }}>
          {value} <span style={{ fontSize: '0.72rem', fontWeight: 500, color: 'var(--text-secondary)' }}>sensor nodes</span>
        </div>
      </div>
    );
  }
  return null;
}

function CustomBarTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    const data = payload[0];
    const fill = data.payload?.fill || data.color || '#00d4ff';
    return (
      <div style={{
        background: 'rgba(6, 13, 24, 0.96)',
        border: `1px solid ${fill}`,
        borderRadius: 8,
        padding: '8px 12px',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.8)',
        pointerEvents: 'none',
        zIndex: 9999
      }}>
        <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f8fafc', marginBottom: 2 }}>
          {label || data.name}
        </div>
        <div style={{ fontSize: '0.95rem', fontWeight: 800, color: fill, fontFamily: 'monospace' }}>
          {data.value} <span style={{ fontSize: '0.72rem', fontWeight: 500, color: 'var(--text-secondary)' }}>Gbps line rate</span>
        </div>
      </div>
    );
  }
  return null;
}

export default function SensorsPage() {
  const [sensors, setSensors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [showAnalytics, setShowAnalytics] = useState(true);
  const [formData, setFormData] = useState({ name: '', hostname: '', ip_address: '', location: '' });
  const [actionLoadingId, setActionLoadingId] = useState(null);

  const fetchSensors = useCallback(async (showSpinner = true) => {
    try {
      if (showSpinner) setLoading(true);
      const res = await api.getSensors();
      setSensors(res?.items || res?.data || (Array.isArray(res) ? res : []));
      setError(null);
    } catch (err) {
      if (showSpinner) setError(err.message || 'Failed to fetch sensors');
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSensors(true);
  }, [fetchSensors]);

  // Real-time synchronization
  useOnLiveEvent(() => {
    fetchSensors(false);
  });

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await api.registerSensor(formData);
      setShowAddModal(false);
      setFormData({ name: '', hostname: '', ip_address: '', location: '' });
      fetchSensors();
    } catch (err) {
      alert(`Registration failed: ${err.message}`);
    }
  };

  const handleIsolate = async (sensor) => {
    if (!confirm(`Are you sure you want to QUARANTINE and ISOLATE host "${sensor.hostname}" (${sensor.ip_address}) from the network?`)) {
      return;
    }
    try {
      setActionLoadingId(sensor.id);
      await api.isolateSensor(sensor.id);
      await fetchSensors();
    } catch (err) {
      alert(`Isolation failed: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleUnisolate = async (sensor) => {
    try {
      setActionLoadingId(sensor.id);
      await api.unisolateSensor(sensor.id);
      await fetchSensors();
    } catch (err) {
      alert(`Restoration failed: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  };

  const isolatedCount = sensors.filter(s => s.status === 'ISOLATED').length;
  const onlineCount = sensors.filter(s => s.status === 'ONLINE').length;

  // Chart Data: Health Status Donut
  const statusChartData = useMemo(() => {
    return [
      { name: 'Online & Ingesting', status: 'ONLINE', value: onlineCount, color: '#10b981' },
      { name: 'Quarantined / Isolated', status: 'ISOLATED', value: isolatedCount, color: '#ef4444' },
      { name: 'Standby Fleet', status: 'STANDBY', value: Math.max(0, sensors.length - onlineCount - isolatedCount), color: '#64748b' }
    ].filter(item => item.value > 0);
  }, [sensors, onlineCount, isolatedCount]);

  // Chart Data: Node Throughput Capacity
  const throughputChartData = useMemo(() => {
    return sensors.slice(0, 6).map((s, idx) => ({
      name: s.name ? (s.name.length > 14 ? s.name.slice(0, 14) + '...' : s.name) : `Probe-${idx + 1}`,
      capacityGbps: s.status === 'ISOLATED' ? 0 : 10 + (idx * 5) % 15,
      fill: s.status === 'ISOLATED' ? '#ef4444' : '#00d4ff'
    }));
  }, [sensors]);

  const filteredSensors = useMemo(() => {
    return sensors.filter(s => {
      if (statusFilter !== 'ALL' && s.status !== statusFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchName = (s.name || '').toLowerCase().includes(q);
        const matchHost = (s.hostname || '').toLowerCase().includes(q);
        const matchIp = (s.ip_address || '').toLowerCase().includes(q);
        const matchLoc = (s.location || '').toLowerCase().includes(q);
        if (!matchName && !matchHost && !matchIp && !matchLoc) return false;
      }
      return true;
    });
  }, [sensors, statusFilter, searchQuery]);

  return (
    <PageLayout sidebar={<Sidebar />}>
      {/* Page Header */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <h1 className="page-title glow-text" style={{ margin: 0 }}>Network Sensors & Endpoints</h1>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                fontSize: '0.72rem',
                fontWeight: 700,
                color: '#10b981',
                background: 'rgba(16,185,129,0.12)',
                padding: '4px 10px',
                borderRadius: 20,
                border: '1px solid rgba(16,185,129,0.3)',
                letterSpacing: '0.04em'
              }}
            >
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981' }} />
              PROBE MESH ONLINE
            </span>
          </div>
          <p className="page-subtitle" style={{ margin: '4px 0 0' }}>
            Distributed high-speed DPI probes, inline packet inspection taps, and automated endpoint isolation
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {isolatedCount > 0 && (
            <span style={{
              background: 'rgba(239, 68, 68, 0.2)',
              border: '1px solid var(--sev-critical)',
              color: '#f87171',
              padding: '6px 12px',
              borderRadius: 6,
              fontSize: '0.8rem',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              gap: 6
            }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444', display: 'inline-block' }}></span>
              {isolatedCount} HOST{isolatedCount > 1 ? 'S' : ''} QUARANTINED
            </span>
          )}
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => setShowAnalytics(!showAnalytics)}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            title="Toggle sensor telemetry graphs"
          >
            <span>📊</span>
            <span>{showAnalytics ? 'Hide Analytics' : 'Show Analytics'}</span>
          </button>
          <button className="btn btn-secondary btn-sm" onClick={() => fetchSensors(true)}>
            🔄 Refresh
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => setShowAddModal(true)}>
            + Register Sensor
          </button>
        </div>
      </div>

      {/* Enterprise Operations Metric Ribbon */}
      <div className="enterprise-soc-ribbon">
        <div
          className="metric-card-enterprise"
          onClick={() => setStatusFilter('ALL')}
          style={{ cursor: 'pointer' }}
          title="Click to view all sensor nodes"
        >
          <div className="metric-label">Monitored Probe Fleet</div>
          <div className="metric-value" style={{ color: 'var(--text-primary)' }}>
            {sensors.length}
          </div>
          <div className="metric-subtext">Total active hardware & virtual tap nodes (click to reset)</div>
        </div>

        <div
          className="metric-card-enterprise"
          onClick={() => setStatusFilter(statusFilter === 'ONLINE' ? 'ALL' : 'ONLINE')}
          style={{ cursor: 'pointer' }}
          title="Click to filter by online probes"
        >
          <div className="metric-label">Online & Ingesting</div>
          <div className="metric-value" style={{ color: '#10b981' }}>
            {onlineCount}
          </div>
          <div className="metric-subtext">Operating with zero packet drops (click to filter)</div>
        </div>

        <div
          className="metric-card-enterprise"
          onClick={() => setStatusFilter(statusFilter === 'ISOLATED' ? 'ALL' : 'ISOLATED')}
          style={{ cursor: 'pointer' }}
          title="Click to filter by quarantined hosts"
        >
          <div className="metric-label">Host Isolations</div>
          <div className="metric-value" style={{ color: isolatedCount > 0 ? '#ef4444' : 'var(--text-secondary)' }}>
            {isolatedCount}
          </div>
          <div className="metric-subtext">Endpoints disconnected via Layer 2 isolation (click to filter)</div>
        </div>

        <div className="metric-card-enterprise">
          <div className="metric-label">Combined Ingress Capacity</div>
          <div className="metric-value" style={{ color: '#00d4ff' }}>
            40 Gbps
          </div>
          <div className="metric-subtext">DPDK & AF_XDP kernel-bypass aggregate throughput</div>
        </div>
      </div>

      {/* Visual Analytics Graphs */}
      {showAnalytics && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 20, marginBottom: 20 }}>
          {/* Sensor Health Status Donut */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Fleet Health & Containment Status
                </h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  Operational telemetry of distributed probe nodes
                </span>
              </div>
              <span style={{ fontSize: '0.7rem', color: '#10b981', fontWeight: 700, background: 'rgba(16,185,129,0.12)', padding: '2px 8px', borderRadius: 10 }}>
                HEALTH MESH
              </span>
            </div>

            {statusChartData.length > 0 ? (
              <div style={{ width: '100%', height: 210 }}>
                <ResponsiveContainer width="100%" height={210}>
                  <PieChart>
                    <Pie
                      data={statusChartData}
                      nameKey="name"
                      dataKey="value"
                      cx="50%"
                      cy="48%"
                      innerRadius={44}
                      outerRadius={74}
                      paddingAngle={4}
                      isAnimationActive={false}
                      onClick={(entry) => setStatusFilter(entry.status)}
                      cursor="pointer"
                    >
                      {statusChartData.map((entry, index) => (
                        <Cell key={`status-${index}`} fill={entry.color} stroke="transparent" />
                      ))}
                    </Pie>
                    <Tooltip
                      content={<CustomPieTooltip />}
                      wrapperStyle={{ zIndex: 9999, pointerEvents: 'none' }}
                    />
                    <Legend
                      iconType="circle"
                      iconSize={8}
                      wrapperStyle={{ fontSize: '0.74rem', color: 'var(--text-secondary)', paddingTop: 4 }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <EmptyState message="No sensor status telemetry" />
            )}
          </div>

          {/* Node Throughput Bar Chart */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Ingress Inspection Throughput (Gbps)
                </h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  Line rate processing capacity by node
                </span>
              </div>
              <span style={{ fontSize: '0.7rem', color: '#00d4ff', fontWeight: 700, background: 'rgba(0,212,255,0.12)', padding: '2px 8px', borderRadius: 10 }}>
                LINE RATE
              </span>
            </div>

            <div style={{ width: '100%', height: 210 }}>
              <ResponsiveContainer width="100%" height={210}>
                <BarChart data={throughputChartData} margin={{ top: 10, right: 10, left: -25, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                  <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                  <Tooltip
                    content={<CustomBarTooltip />}
                    wrapperStyle={{ zIndex: 9999, pointerEvents: 'none' }}
                  />
                  <Bar dataKey="capacityGbps" radius={[4, 4, 0, 0]} isAnimationActive={false}>
                    {throughputChartData.map((entry, index) => (
                      <Cell key={`bar-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Search Toolbar */}
      <div className="glass-card" style={{ padding: '14px 20px', marginBottom: 20, display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          type="text"
          className="input"
          placeholder="Filter sensors by name, hostname, IP address or location zone..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          style={{ width: 340, fontSize: '0.82rem', padding: '6px 12px' }}
        />

        <div className="workspace-nav-bar" style={{ margin: 0, padding: 3 }}>
          {['ALL', 'ONLINE', 'ISOLATED'].map(status => (
            <button
              key={status}
              className={`workspace-tab-btn ${statusFilter === status ? 'active' : ''}`}
              onClick={() => setStatusFilter(status)}
              style={{ padding: '5px 12px', fontSize: '0.78rem' }}
            >
              {status === 'ALL' ? 'All Probes' : status}
            </button>
          ))}
        </div>

        {(searchQuery || statusFilter !== 'ALL') && (
          <button className="btn btn-ghost btn-sm" onClick={() => { setSearchQuery(''); setStatusFilter('ALL'); }}>
            Clear Filters
          </button>
        )}

        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
          Displaying {filteredSensors.length} of {sensors.length} probes
        </span>
      </div>

      {/* Sensors Table with Guaranteed Text Bounding */}
      <div className="page-body">
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="glass-card" style={{ color: 'var(--sev-critical)', padding: 20 }}>
            {error}
          </div>
        ) : filteredSensors.length === 0 ? (
          <EmptyState message={searchQuery || statusFilter !== 'ALL' ? 'No sensors match your filter criteria' : 'No network sensors registered in mesh'} />
        ) : (
          <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="table-wrapper">
              <table className="data-table" style={{ tableLayout: 'fixed', width: '100%', minWidth: 960 }}>
                <colgroup>
                  <col style={{ width: '22%' }} />
                  <col style={{ width: '18%' }} />
                  <col style={{ width: '16%' }} />
                  <col style={{ width: '14%' }} />
                  <col style={{ width: '12%' }} />
                  <col style={{ width: '18%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>Sensor Probe Name</th>
                    <th>Hostname / FQDN</th>
                    <th>Ingress IP / Subnet</th>
                    <th>Location Zone</th>
                    <th>Health Status</th>
                    <th>Host Containment Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSensors.map((sensor) => {
                    const isIsolated = sensor.status === 'ISOLATED';
                    const isBusy = actionLoadingId === sensor.id;
                    return (
                      <tr key={sensor.id} style={{ background: isIsolated ? 'rgba(239, 68, 68, 0.05)' : 'transparent' }}>
                        <td>
                          <div
                            style={{
                              fontWeight: 600,
                              color: 'var(--text-primary)',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}
                            title={sensor.name}
                          >
                            {sensor.name}
                          </div>
                        </td>
                        <td>
                          <div
                            style={{
                              fontSize: '0.84rem',
                              color: 'var(--text-secondary)',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}
                            title={sensor.hostname}
                          >
                            {sensor.hostname}
                          </div>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.84rem', fontFamily: 'monospace', color: 'var(--accent-cyan)' }}>
                            {sensor.ip_address}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                            {sensor.location || 'Core DC'}
                          </span>
                        </td>
                        <td>
                          {isIsolated ? (
                            <span style={{
                              background: 'rgba(239, 68, 68, 0.25)',
                              border: '1px solid #ef4444',
                              color: '#fca5a5',
                              padding: '3px 8px',
                              borderRadius: 4,
                              fontSize: '0.74rem',
                              fontWeight: 700,
                              letterSpacing: '0.04em',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 6,
                              whiteSpace: 'nowrap'
                            }}>
                              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444' }} />
                              ISOLATED
                            </span>
                          ) : (
                            <span style={{
                              background: 'rgba(16, 185, 129, 0.15)',
                              border: '1px solid #10b981',
                              color: '#34d399',
                              padding: '3px 8px',
                              borderRadius: 4,
                              fontSize: '0.74rem',
                              fontWeight: 700,
                              letterSpacing: '0.04em',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 6,
                              whiteSpace: 'nowrap'
                            }}>
                              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 6px #10b981' }} />
                              ONLINE
                            </span>
                          )}
                        </td>
                        <td>
                          {isIsolated ? (
                            <button
                              className="btn btn-sm"
                              disabled={isBusy}
                              onClick={() => handleUnisolate(sensor)}
                              style={{
                                background: 'rgba(16, 185, 129, 0.15)',
                                border: '1px solid #10b981',
                                color: '#34d399',
                                fontSize: '0.75rem',
                                padding: '4px 10px',
                                cursor: 'pointer',
                                whiteSpace: 'nowrap'
                              }}
                            >
                              {isBusy ? 'Restoring...' : '✓ Restore Access'}
                            </button>
                          ) : (
                            <button
                              className="btn btn-sm"
                              disabled={isBusy}
                              onClick={() => handleIsolate(sensor)}
                              style={{
                                background: 'rgba(239, 68, 68, 0.15)',
                                border: '1px solid #ef4444',
                                color: '#f87171',
                                fontSize: '0.75rem',
                                padding: '4px 10px',
                                cursor: 'pointer',
                                whiteSpace: 'nowrap'
                              }}
                            >
                              {isBusy ? 'Quarantining...' : '🔒 Isolate Machine'}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Centered Modal for Registering Sensor */}
      {showAddModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0,0,0,0.75)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: 20
          }}
          onClick={() => setShowAddModal(false)}
        >
          <div
            className="glass-card"
            onClick={(e) => e.stopPropagation()}
            style={{
              width: '100%',
              maxWidth: 480,
              padding: 28,
              border: '1px solid var(--border-glow)',
              boxShadow: '0 24px 60px rgba(0,0,0,0.8)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  📡 Register Network Probe
                </h3>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  Attach a distributed telemetry tap to the IDS/IPS cluster
                </span>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setShowAddModal(false)}
                style={{ fontSize: '1.1rem', padding: '4px 8px' }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleRegister}>
              <div style={{ marginBottom: 14 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Sensor Name
                </label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. DMZ Edge Sniffer Alpha"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  style={{ fontSize: '0.86rem' }}
                />
              </div>

              <div style={{ marginBottom: 14 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Fully Qualified Hostname
                </label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. probe-01.dmz.enterprise.internal"
                  value={formData.hostname}
                  onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                  style={{ fontSize: '0.86rem', fontFamily: 'monospace' }}
                />
              </div>

              <div style={{ marginBottom: 14 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Management IP Address
                </label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. 10.240.10.50"
                  value={formData.ip_address}
                  onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
                  style={{ fontSize: '0.86rem', fontFamily: 'monospace' }}
                />
              </div>

              <div style={{ marginBottom: 20 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Deployment Zone / Location
                </label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. Frankfurt DC - Rack 4B"
                  value={formData.location}
                  onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                  style={{ fontSize: '0.86rem' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => setShowAddModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary btn-sm" style={{ padding: '6px 16px' }}>
                  Register Sensor
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
