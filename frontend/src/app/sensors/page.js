'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, StatusBadge, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';

export default function SensorsPage() {
  const [sensors, setSensors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [formData, setFormData] = useState({ name: '', hostname: '', ip_address: '', location: '' });

  const fetchSensors = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getSensors();
      setSensors(res?.items || res?.data || (Array.isArray(res) ? res : []));
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to fetch sensors');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSensors();
  }, [fetchSensors]);

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

  const [actionLoadingId, setActionLoadingId] = useState(null);

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

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Network Sensors & Endpoints</h1>
          <p className="page-subtitle">Monitored probes, inline agents, and automated machine quarantine</p>
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
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444', display: 'inline-block', animation: 'pulse 1.5s infinite' }}></span>
              {isolatedCount} MACHINE{isolatedCount > 1 ? 'S' : ''} QUARANTINED
            </span>
          )}
          <button className="btn btn-primary btn-sm" onClick={() => setShowAddModal(true)}>
            + Register Sensor
          </button>
        </div>
      </div>

      {/* Metric summary banner */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16, marginBottom: 20 }}>
        <div className="glass-card" style={{ padding: '14px 20px', borderLeft: '4px solid var(--accent-primary)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Monitored</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, marginTop: 4 }}>{sensors.length}</div>
        </div>
        <div className="glass-card" style={{ padding: '14px 20px', borderLeft: '4px solid #10b981' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Active Online</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#34d399', marginTop: 4 }}>{onlineCount}</div>
        </div>
        <div className="glass-card" style={{ padding: '14px 20px', borderLeft: '4px solid var(--sev-critical)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Quarantined / Isolated</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: isolatedCount > 0 ? '#f87171' : 'var(--text-secondary)', marginTop: 4 }}>{isolatedCount}</div>
        </div>
      </div>

      <div className="page-body">
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="glass-card" style={{ color: 'var(--sev-critical)', padding: 20 }}>
            {error}
          </div>
        ) : sensors.length === 0 ? (
          <EmptyState message="No network sensors registered" />
        ) : (
          <div className="glass-card">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Sensor Name</th>
                  <th>Hostname</th>
                  <th>IP Address</th>
                  <th>Location</th>
                  <th>Status</th>
                  <th>Host Containment</th>
                  <th>Registered</th>
                </tr>
              </thead>
              <tbody>
                {sensors.map((sensor) => {
                  const isIsolated = sensor.status === 'ISOLATED';
                  const isBusy = actionLoadingId === sensor.id;
                  return (
                    <tr key={sensor.id} style={{ background: isIsolated ? 'rgba(239, 68, 68, 0.05)' : 'transparent' }}>
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {sensor.name}
                      </td>
                      <td style={{ fontSize: '0.85rem' }}>{sensor.hostname}</td>
                      <td style={{ fontSize: '0.85rem', fontFamily: 'monospace' }}>{sensor.ip_address}</td>
                      <td style={{ fontSize: '0.85rem' }}>{sensor.location || 'N/A'}</td>
                      <td>
                        {isIsolated ? (
                          <span style={{
                            background: 'rgba(239, 68, 68, 0.25)',
                            border: '1px solid #ef4444',
                            color: '#fca5a5',
                            padding: '3px 8px',
                            borderRadius: 4,
                            fontSize: '0.75rem',
                            fontWeight: 700,
                            letterSpacing: '0.05em',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 4
                          }}>
                            ISOLATED
                          </span>
                        ) : (
                          <StatusBadge status={sensor.status} />
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
                              cursor: 'pointer'
                            }}
                          >
                            {isBusy ? 'Restoring...' : 'Restore Access'}
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
                              cursor: 'pointer'
                            }}
                          >
                            {isBusy ? 'Quarantining...' : 'Isolate Machine'}
                          </button>
                        )}
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        {sensor.created_at ? new Date(sensor.created_at).toLocaleString() : 'Never'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal for Registering Sensor */}
      {showAddModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999
        }} onClick={() => setShowAddModal(false)}>
          <div className="glass-card" onClick={(e) => e.stopPropagation()} style={{ width: '100%', maxWidth: 440, padding: 24 }}>
            <h3 style={{ marginTop: 0, marginBottom: 16 }}>Register New Sensor</h3>
            <form onSubmit={handleRegister}>
              <div style={{ marginBottom: 12 }}>
                <label className="label">Sensor Name</label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. DMZ Probe Alpha"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                />
              </div>
              <div style={{ marginBottom: 12 }}>
                <label className="label">Hostname</label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. sensor-01.dmz.internal"
                  value={formData.hostname}
                  onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                />
              </div>
              <div style={{ marginBottom: 12 }}>
                <label className="label">IP Address</label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. 192.168.10.50"
                  value={formData.ip_address}
                  onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
                />
              </div>
              <div style={{ marginBottom: 20 }}>
                <label className="label">Location / Zone</label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. US-East DataCenter"
                  value={formData.location}
                  onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button type="button" className="btn btn-ghost" onClick={() => setShowAddModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
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
