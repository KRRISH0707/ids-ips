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
      setIncidents(res.data || []);
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
      await api.updateIncident(id, { status });
      fetchIncidents();
      if (selectedIncident && selectedIncident.id === id) {
        setSelectedIncident(prev => ({ ...prev, status }));
      }
    } catch (err) {
      alert(`Failed to update status: ${err.message}`);
    }
  };

  return (
    <Sidebar>
      <PageLayout
        title="Security Incidents"
        subtitle="Aggregated threat cases requiring investigation and response"
        actions={
          <button className="btn btn-primary btn-sm" onClick={fetchIncidents}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21.5 2v6h-6M2.13 15.57a10 10 0 1 0 0-7.14" />
            </svg>
            Refresh
          </button>
        }
      >
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="card" style={{ borderColor: 'var(--color-danger-border)', color: 'var(--color-danger)' }}>
            {error}
          </div>
        ) : incidents.length === 0 ? (
          <EmptyState
            title="No Incidents Reported"
            description="There are currently no open or active security incident cases."
          />
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Assigned To</th>
                  <th>Created At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => (
                  <tr key={inc.id} style={{ cursor: 'pointer' }} onClick={() => setSelectedIncident(inc)}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      #{inc.id}
                    </td>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{inc.title}</td>
                    <td>
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td>
                      <StatusBadge status={inc.status} />
                    </td>
                    <td style={{ fontSize: '0.85rem' }}>{inc.assigned_to || 'Unassigned'}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {new Date(inc.created_at).toLocaleString()}
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <select
                        className="form-select form-select-sm"
                        value={inc.status}
                        onChange={(e) => handleUpdateStatus(inc.id, e.target.value)}
                        style={{ width: 'auto', padding: '2px 8px', fontSize: '0.8rem' }}
                      >
                        <option value="open">Open</option>
                        <option value="investigating">Investigating</option>
                        <option value="mitigated">Mitigated</option>
                        <option value="closed">Closed</option>
                        <option value="false_positive">False Positive</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Modal Drawer for Incident Details */}
        {selectedIncident && (
          <div className="modal-backdrop" onClick={() => setSelectedIncident(null)}>
            <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 600 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700 }}>{selectedIncident.title}</h3>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Incident ID: #{selectedIncident.id}
                  </span>
                </div>
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => setSelectedIncident(null)}
                  style={{ padding: '2px 8px' }}
                >
                  ✕
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                <div>
                  <label className="form-label">Severity</label>
                  <div><SeverityBadge severity={selectedIncident.severity} /></div>
                </div>
                <div>
                  <label className="form-label">Status</label>
                  <div><StatusBadge status={selectedIncident.status} /></div>
                </div>
                <div>
                  <label className="form-label">Assigned To</label>
                  <div style={{ fontSize: '0.9rem' }}>{selectedIncident.assigned_to || 'Unassigned'}</div>
                </div>
                <div>
                  <label className="form-label">Created At</label>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                    {new Date(selectedIncident.created_at).toLocaleString()}
                  </div>
                </div>
              </div>

              <div style={{ marginBottom: 16 }}>
                <label className="form-label">Description</label>
                <p style={{ fontSize: '0.9rem', background: 'var(--surface-hover)', padding: 12, borderRadius: 6 }}>
                  {selectedIncident.description || 'No detailed description provided.'}
                </p>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button className="btn btn-ghost" onClick={() => setSelectedIncident(null)}>
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
      </PageLayout>
    </Sidebar>
  );
}
