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
      setSensors(res.data || []);
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
    <Sidebar>
      <PageLayout
        title="Network Sensors"
        subtitle="Monitored probes, inline agents, and packet capture nodes"
        actions={
          <button className="btn btn-primary btn-sm" onClick={() => setShowAddModal(true)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 5v14M5 12h14" />
            </svg>
            Register Sensor
          </button>
        }
      >
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="card" style={{ borderColor: 'var(--color-danger-border)', color: 'var(--color-danger)' }}>
            {error}
          </div>
        ) : sensors.length === 0 ? (
          <EmptyState
            title="No Sensors Registered"
            description="Register a sensor probe to start capturing traffic anomalies and telemetry."
          />
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Sensor Name</th>
                  <th>Hostname</th>
                  <th>IP Address</th>
                  <th>Location</th>
                  <th>Status</th>
                  <th>Last Heartbeat</th>
                </tr>
              </thead>
              <tbody>
                {sensors.map((sensor) => (
                  <tr key={sensor.id}>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{sensor.name}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{sensor.hostname}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{sensor.ip_address}</td>
                    <td style={{ fontSize: '0.85rem' }}>{sensor.location || 'N/A'}</td>
                    <td>
                      <StatusBadge status={sensor.status} />
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {sensor.last_heartbeat ? new Date(sensor.last_heartbeat).toLocaleString() : 'Never'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Modal for Registering Sensor */}
        {showAddModal && (
          <div className="modal-backdrop" onClick={() => setShowAddModal(false)}>
            <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 480 }}>
              <h3 style={{ marginTop: 0, marginBottom: 16 }}>Register New Sensor</h3>
              <form onSubmit={handleRegister}>
                <div className="form-group">
                  <label className="form-label">Sensor Name</label>
                  <input
                    type="text"
                    className="form-input"
                    required
                    placeholder="e.g. DMZ Probe Alpha"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Hostname</label>
                  <input
                    type="text"
                    className="form-input"
                    required
                    placeholder="e.g. sensor-01.dmz.internal"
                    value={formData.hostname}
                    onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">IP Address</label>
                  <input
                    type="text"
                    className="form-input"
                    required
                    placeholder="e.g. 192.168.10.50"
                    value={formData.ip_address}
                    onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Location / Zone</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g. US-East DataCenter Rack 4"
                    value={formData.location}
                    onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                  />
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 24 }}>
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
    </Sidebar>
  );
}
