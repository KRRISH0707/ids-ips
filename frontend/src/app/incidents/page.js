'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, SeverityBadge, StatusBadge, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);

  const fetchIncidents = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getIncidents();
      setIncidents(res?.items || res?.data || (Array.isArray(res) ? res : []));
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to fetch incidents');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  const handleUpdateStatus = async (id, status) => {
    try {
      await api.updateIncidentStatus(id, { status });
      fetchIncidents();
      if (selectedIncident && selectedIncident.id === id) {
        setSelectedIncident(prev => ({ ...prev, status }));
      }
    } catch (err) {
      alert(`Failed to update status: ${err.message}`);
    }
  };

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Incidents</h1>
          <p className="page-subtitle">Aggregated threat cases requiring investigation and response</p>
        </div>
        <button className="btn btn-primary btn-sm" onClick={fetchIncidents}>
          Refresh
        </button>
      </div>

      <div className="page-body">
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="glass-card" style={{ color: 'var(--sev-critical)', padding: 20 }}>
            {error}
          </div>
        ) : incidents.length === 0 ? (
          <EmptyState message="No security incidents reported" />
        ) : (
          <div className="glass-card">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Risk</th>
                  <th>Created At</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => (
                  <tr key={inc.id} style={{ cursor: 'pointer' }} onClick={() => setSelectedIncident(inc)}>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{inc.title}</td>
                    <td>
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td>
                      <StatusBadge status={inc.status} />
                    </td>
                    <td style={{ fontSize: '0.85rem' }}>{inc.risk_score}</td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {new Date(inc.created_at).toLocaleString()}
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <select
                        className="select"
                        value={inc.status}
                        onChange={(e) => handleUpdateStatus(inc.id, e.target.value)}
                        style={{ width: 140, padding: '4px 8px', fontSize: '0.75rem' }}
                      >
                        <option value="NEW">New</option>
                        <option value="INVESTIGATING">Investigating</option>
                        <option value="CONTAINED">Contained</option>
                        <option value="RESOLVED">Resolved</option>
                        <option value="FALSE_POSITIVE">False Positive</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal Drawer for Incident Details */}
      {selectedIncident && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999
        }} onClick={() => setSelectedIncident(null)}>
          <div className="glass-card" onClick={(e) => e.stopPropagation()} style={{ width: '100%', maxWidth: 540, padding: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700 }}>{selectedIncident.title}</h3>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  ID: #{selectedIncident.id}
                </span>
              </div>
              <button className="btn btn-ghost btn-sm" onClick={() => setSelectedIncident(null)}>✕</button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block' }}>Severity</label>
                <SeverityBadge severity={selectedIncident.severity} />
              </div>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block' }}>Status</label>
                <StatusBadge status={selectedIncident.status} />
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Description</label>
              <p style={{ fontSize: '0.85rem', background: 'var(--bg-card)', padding: 12, borderRadius: 6 }}>
                {selectedIncident.description || 'No detailed description provided.'}
              </p>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-ghost" onClick={() => setSelectedIncident(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
