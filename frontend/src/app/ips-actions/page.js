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
  const [formData, setFormData] = useState({ ip_address: '', reason: '', duration_minutes: 60 });

  const fetchBlockedIPs = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getBlockedIPs();
      setBlockedIPs(res.data || []);
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
      setFormData({ ip_address: '', reason: '', duration_minutes: 60 });
      fetchBlockedIPs();
    } catch (err) {
      alert(`Block operation failed: ${err.message}`);
    }
  };

  const handleUnblock = async (ip) => {
    if (!confirm(`Are you sure you want to unblock IP address ${ip}?`)) return;
    try {
      await api.unblockIP(ip);
      fetchBlockedIPs();
    } catch (err) {
      alert(`Unblock operation failed: ${err.message}`);
    }
  };

  return (
    <Sidebar>
      <PageLayout
        title="IPS Active Blocking"
        subtitle="Automated & manual IP firewall blocklist enforced by IPS controller"
        actions={
          <button className="btn btn-danger btn-sm" onClick={() => setShowModal(true)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            Block IP Address
          </button>
        }
      >
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="card" style={{ borderColor: 'var(--color-danger-border)', color: 'var(--color-danger)' }}>
            {error}
          </div>
        ) : blockedIPs.length === 0 ? (
          <EmptyState
            title="No Active IP Blocks"
            description="The IPS firewall enforcement module currently has no active blocklist entries."
          />
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Reason / Threat</th>
                  <th>Blocked By</th>
                  <th>Blocked At</th>
                  <th>Expires At</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {blockedIPs.map((entry) => (
                  <tr key={entry.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-danger)' }}>
                      {entry.ip_address}
                    </td>
                    <td style={{ fontSize: '0.85rem' }}>{entry.reason}</td>
                    <td style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{entry.blocked_by || 'IPS Engine'}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {new Date(entry.blocked_at).toLocaleString()}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {entry.expires_at ? new Date(entry.expires_at).toLocaleString() : 'Permanent'}
                    </td>
                    <td>
                      <StatusBadge status={entry.is_active ? 'active' : 'expired'} />
                    </td>
                    <td>
                      {entry.is_active && (
                        <button
                          className="btn btn-ghost btn-sm"
                          style={{ color: 'var(--color-danger)', padding: '2px 8px', fontSize: '0.75rem' }}
                          onClick={() => handleUnblock(entry.ip_address)}
                        >
                          Unblock
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Modal to Block IP */}
        {showModal && (
          <div className="modal-backdrop" onClick={() => setShowModal(false)}>
            <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 480 }}>
              <h3 style={{ marginTop: 0, marginBottom: 16 }}>Enforce IP Firewall Block</h3>
              <form onSubmit={handleBlock}>
                <div className="form-group">
                  <label className="form-label">Target IP Address</label>
                  <input
                    type="text"
                    className="form-input"
                    required
                    placeholder="e.g. 198.51.100.42"
                    value={formData.ip_address}
                    onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Reason for Block</label>
                  <input
                    type="text"
                    className="form-input"
                    required
                    placeholder="e.g. SSH Brute Force / Malicious Recon"
                    value={formData.reason}
                    onChange={(e) => setFormData({ ...formData, reason: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Duration (Minutes)</label>
                  <input
                    type="number"
                    className="form-input"
                    min="5"
                    max="10080"
                    value={formData.duration_minutes}
                    onChange={(e) => setFormData({ ...formData, duration_minutes: parseInt(e.target.value) })}
                  />
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 24 }}>
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
    </Sidebar>
  );
}
