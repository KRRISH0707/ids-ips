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

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Network Sensors</h1>
          <p className="page-subtitle">Monitored probes, inline agents, and packet capture nodes</p>
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setShowAddModal(true)}>
          + Register Sensor
        </button>
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
                  <th>Created At</th>
                </tr>
              </thead>
              <tbody>
                {sensors.map((sensor) => (
                  <tr key={sensor.id}>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{sensor.name}</td>
                    <td style={{ fontSize: '0.85rem' }}>{sensor.hostname}</td>
                    <td style={{ fontSize: '0.85rem', fontFamily: 'monospace' }}>{sensor.ip_address}</td>
                    <td style={{ fontSize: '0.85rem' }}>{sensor.location || 'N/A'}</td>
                    <td>
                      <StatusBadge status={sensor.status} />
                    </td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {sensor.created_at ? new Date(sensor.created_at).toLocaleString() : 'Never'}
                    </td>
                  </tr>
                ))}
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
