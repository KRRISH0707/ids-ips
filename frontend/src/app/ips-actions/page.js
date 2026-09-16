'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, StatusBadge, Spinner, EmptyState } from '@/components/ui';
import { api, getUser } from '@/lib/api';

export default function IPSActionsPage() {
  const currentUser = getUser();
  const isViewer = currentUser?.role === 'VIEWER';

  const [blockedIPs, setBlockedIPs] = useState([]);
  const [loading, setLoading] = useState(!isViewer);
  const [error, setError] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({ target: '', reason: '', duration_minutes: 60 });

  const fetchBlockedIPs = useCallback(async () => {
    if (isViewer) return;
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
  }, [isViewer]);

  useEffect(() => {
    if (!isViewer) {
      fetchBlockedIPs();
    }
  }, [fetchBlockedIPs, isViewer]);

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
        {!isViewer && (
          <button className="btn btn-danger btn-sm" onClick={() => setShowModal(true)}>
            🛡️ Block IP Address
          </button>
        )}
      </div>

      <div className="page-body">
        {isViewer ? (
          <div className="glass-card" style={{ padding: 40, textAlign: 'center', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
            <div style={{ width: 56, height: 56, borderRadius: '50%', background: 'rgba(239, 68, 68, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', color: '#ef4444' }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
              IPS Controls Restricted
            </h3>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', maxWidth: 480, margin: '0 auto 16px', lineHeight: 1.6 }}>
              Your active role is <span style={{ color: '#94a3b8', fontWeight: 600 }}>VIEWER</span>. In accordance with the SOC Two-Layer Defense Matrix, active IPS firewall mitigation and IP blocklist controls require <span style={{ color: '#00d4ff', fontWeight: 600 }}>ANALYST</span> or <span style={{ color: '#a855f7', fontWeight: 600 }}>ADMIN</span> privileges.
            </p>
            <div style={{ display: 'inline-flex', gap: 12, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              <span>👁️ Viewers have read-only telemetry privileges on Alerts and Incidents.</span>
            </div>
          </div>
        ) : loading ? (
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
