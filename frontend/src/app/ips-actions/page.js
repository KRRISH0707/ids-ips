'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, StatusBadge, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';

export default function IPSActionsPage() {
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({ target: '', reason: '', duration_minutes: 60 });

  const fetchBlockedIPs = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getBlockedIPs();
      setBlockedIPs(res?.items || res?.data || (Array.isArray(res) ? res : []));
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to fetch blocked IPs');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchBlockedIPs();
  }, [fetchBlockedIPs]);

  const handleBlock = async (e) => {
    e.preventDefault();
    try {
      await api.blockIP(formData);
      setShowModal(false);
      setFormData({ target: '', reason: '', duration_minutes: 60 });
      fetchBlockedIPs();
    } catch (err) {
      alert(`Block operation failed: ${err.message}`);
    }
  };

  const handleUnblock = async (id) => {
    if (!confirm(`Are you sure you want to unblock this item?`)) return;
    try {
      await api.unblockIP(id, 'Manual Analyst Unblock');
      fetchBlockedIPs();
    } catch (err) {
      alert(`Unblock operation failed: ${err.message}`);
    }
  };

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title">IPS Active Mitigation</h1>
          <p className="page-subtitle">Automated & manual firewall blocklist enforced by IPS controller</p>
        </div>
        <button className="btn btn-danger btn-sm" onClick={() => setShowModal(true)}>
          🛡️ Block IP Address
        </button>
      </div>

      <div className="page-body">
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="glass-card" style={{ color: 'var(--sev-critical)', padding: 20 }}>
            {error}
          </div>
        ) : blockedIPs.length === 0 ? (
          <EmptyState message="No active IP blocks in firewall registry" />
        ) : (
          <div className="glass-card">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Target IP</th>
                  <th>Action</th>
                  <th>Reason</th>
                  <th>Status</th>
                  <th>Created At</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {blockedIPs.map((entry) => (
                  <tr key={entry.id}>
                    <td style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--sev-critical)' }}>
                      {entry.target || entry.ip_address}
                    </td>
                    <td style={{ fontSize: '0.85rem' }}>{entry.action}</td>
                    <td style={{ fontSize: '0.85rem' }}>{entry.reason}</td>
                    <td>
                      <StatusBadge status={entry.status} />
                    </td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {entry.created_at ? new Date(entry.created_at).toLocaleString() : '—'}
                    </td>
                    <td>
                      {entry.status === 'APPLIED' || entry.status === 'PENDING' ? (
                        <button
                          className="btn btn-ghost btn-sm"
                          style={{ color: 'var(--sev-critical)', padding: '2px 8px', fontSize: '0.75rem' }}
                          onClick={() => handleUnblock(entry.id)}
                        >
                          Unblock
                        </button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal to Block IP */}
      {showModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999
        }} onClick={() => setShowModal(false)}>
          <div className="glass-card" onClick={(e) => e.stopPropagation()} style={{ width: '100%', maxWidth: 440, padding: 24 }}>
            <h3 style={{ marginTop: 0, marginBottom: 16 }}>Enforce IP Firewall Block</h3>
            <form onSubmit={handleBlock}>
              <div style={{ marginBottom: 12 }}>
                <label className="label">Target IP Address</label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. 198.51.100.42"
                  value={formData.target}
                  onChange={(e) => setFormData({ ...formData, target: e.target.value })}
                />
              </div>
              <div style={{ marginBottom: 12 }}>
                <label className="label">Reason for Block</label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. SSH Brute Force / Malicious Recon"
                  value={formData.reason}
                  onChange={(e) => setFormData({ ...formData, reason: e.target.value })}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 20 }}>
                <button type="button" className="btn btn-ghost" onClick={() => setShowModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-danger">
                  Enforce Block
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
