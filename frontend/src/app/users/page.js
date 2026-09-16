'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, Spinner, EmptyState } from '@/components/ui';
import { api, getUser } from '@/lib/api';

export default function UsersPage() {
  const currentUser = getUser();
  const isAdmin = currentUser?.role === 'ADMIN';

  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    full_name: '',
    password: '',
    role: 'ANALYST'
  });
  const [submitting, setSubmitting] = useState(false);

  const fetchUsers = useCallback(async () => {
    if (!isAdmin) {
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const res = await api.getUsers();
      setUsers(res?.items || res?.data || (Array.isArray(res) ? res : []));
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to fetch users');
    } finally {
      setLoading(false);
    }
  }, [isAdmin]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    try {
      setSubmitting(true);
      await api.createUser(formData);
      setShowAddModal(false);
      setFormData({ email: '', full_name: '', password: '', role: 'ANALYST' });
      await fetchUsers();
    } catch (err) {
      alert(`User creation failed: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteUser = async (user) => {
    if (user.id === currentUser?.id) {
      alert('You cannot delete your own active administrator account!');
      return;
    }
    if (!confirm(`Are you sure you want to revoke access for ${user.email} (${user.role})?`)) {
      return;
    }
    try {
      await api.deleteUser(user.id);
      await fetchUsers();
    } catch (err) {
      alert(`Failed to delete user: ${err.message}`);
    }
  };

  return (
    <Sidebar>
      <PageLayout
        title="Role-Based Access Control & User Fleet"
        subtitle="Manage operators, analysts, viewers, and granular backend access policies"
        actions={
          isAdmin && (
            <button
              onClick={() => setShowAddModal(true)}
              className="btn btn-primary"
              style={{ display: 'flex', alignItems: 'center', gap: 8 }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                <circle cx="8.5" cy="7" r="4" />
                <line x1="20" y1="8" x2="20" y2="14" />
                <line x1="23" y1="11" x2="17" y2="11" />
              </svg>
              Add SOC Operator
            </button>
          )
        }
      >
        {/* Role Matrix Card */}
        <div className="glass-card" style={{ padding: 24, marginBottom: 24, border: '1px solid var(--border-bright)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'var(--accent-cyan)' }} />
            <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Two-Layer Enterprise Defense & RBAC Permissions Matrix
            </h3>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', marginBottom: 20 }}>
            <strong>Layer 1 (Perimeter):</strong> Cloudflare Access verifies email identities at the network edge.
            <br />
            <strong>Layer 2 (Granular RBAC):</strong> FastAPI cryptographically enforces fine-grained operator scopes via JWT claims.
          </p>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '10px 14px' }}>ROLE</th>
                  <th style={{ padding: '10px 14px' }}>DASHBOARD</th>
                  <th style={{ padding: '10px 14px' }}>ALERTS & DPI</th>
                  <th style={{ padding: '10px 14px' }}>INCIDENTS</th>
                  <th style={{ padding: '10px 14px' }}>IPS CONTROLS</th>
                  <th style={{ padding: '10px 14px' }}>USER FLEET</th>
                </tr>
              </thead>
              <tbody>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '12px 14px', fontWeight: 700, color: '#a855f7' }}>
                    <span style={{ padding: '3px 8px', borderRadius: 4, background: 'rgba(168, 85, 247, 0.15)', border: '1px solid rgba(168, 85, 247, 0.4)' }}>
                      ADMIN
                    </span>
                  </td>
                  <td style={{ padding: '12px 14px', color: '#10b981' }}>✅ Full Access</td>
                  <td style={{ padding: '12px 14px', color: '#10b981' }}>✅ Full Ingestion & DPI</td>
                  <td style={{ padding: '12px 14px', color: '#10b981' }}>✅ Create / Mitigate</td>
                  <td style={{ padding: '12px 14px', color: '#10b981' }}>✅ Block / Unblock</td>
                  <td style={{ padding: '12px 14px', color: '#10b981' }}>✅ Full Control</td>
                </tr>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '12px 14px', fontWeight: 700, color: '#00d4ff' }}>
                    <span style={{ padding: '3px 8px', borderRadius: 4, background: 'rgba(0, 212, 255, 0.15)', border: '1px solid rgba(0, 212, 255, 0.4)' }}>
                      ANALYST
                    </span>
                  </td>
                  <td style={{ padding: '12px 14px', color: '#10b981' }}>✅ Full Access</td>
                  <td style={{ padding: '12px 14px', color: '#10b981' }}>✅ Full Ingestion & DPI</td>
                  <td style={{ padding: '12px 14px', color: '#10b981' }}>✅ Create / Mitigate</td>
                  <td style={{ padding: '12px 14px', color: '#10b981' }}>✅ Block / Unblock</td>
                  <td style={{ padding: '12px 14px', color: '#ef4444' }}>❌ Restricted</td>
                </tr>
                <tr>
                  <td style={{ padding: '12px 14px', fontWeight: 700, color: '#94a3b8' }}>
                    <span style={{ padding: '3px 8px', borderRadius: 4, background: 'rgba(148, 163, 184, 0.15)', border: '1px solid rgba(148, 163, 184, 0.4)' }}>
                      VIEWER
                    </span>
                  </td>
                  <td style={{ padding: '12px 14px', color: '#10b981' }}>✅ Full Access</td>
                  <td style={{ padding: '12px 14px', color: '#10b981' }}>✅ Read Telemetry</td>
                  <td style={{ padding: '12px 14px', color: '#f59e0b' }}>👁️ Read-Only</td>
                  <td style={{ padding: '12px 14px', color: '#ef4444' }}>❌ Restricted</td>
                  <td style={{ padding: '12px 14px', color: '#ef4444' }}>❌ Restricted</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Access Denied Banner for Non-Admin */}
        {!isAdmin && (
          <div className="glass-card" style={{ padding: 36, textAlign: 'center', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
            <div style={{ width: 52, height: 52, borderRadius: '50%', background: 'rgba(239, 68, 68, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', color: '#ef4444' }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
            <h3 style={{ margin: '0 0 8px', color: 'var(--text-primary)' }}>Administrator Privileges Required</h3>
            <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.88rem' }}>
              Your account currently has the <strong>{currentUser?.role || 'VIEWER'}</strong> role. Only users with the <strong>ADMIN</strong> role can add, modify, or revoke operator credentials.
            </p>
          </div>
        )}

        {/* User Fleet Table (Admin Only) */}
        {isAdmin && (
          <div className="glass-card" style={{ padding: 24 }}>
            <h3 style={{ margin: '0 0 16px', fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Active Authorized Operators ({users.length})
            </h3>

            {loading ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
                <Spinner />
              </div>
            ) : error ? (
              <div style={{ color: 'var(--sev-critical)', padding: 16 }}>{error}</div>
            ) : users.length === 0 ? (
              <EmptyState message="No operators found" />
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-muted)' }}>
                      <th style={{ padding: '10px 14px' }}>OPERATOR / EMAIL</th>
                      <th style={{ padding: '10px 14px' }}>FULL NAME</th>
                      <th style={{ padding: '10px 14px' }}>ASSIGNED ROLE</th>
                      <th style={{ padding: '10px 14px' }}>STATUS</th>
                      <th style={{ padding: '10px 14px' }}>REGISTERED</th>
                      <th style={{ padding: '10px 14px', textAlign: 'right' }}>ACTIONS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((u) => (
                      <tr key={u.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '14px' }}>
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.email}</div>
                          {u.email === currentUser?.email && (
                            <span style={{ fontSize: '0.68rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>
                              (You — Active Session)
                            </span>
                          )}
                        </td>
                        <td style={{ padding: '14px', color: 'var(--text-secondary)' }}>
                          {u.full_name || '—'}
                        </td>
                        <td style={{ padding: '14px' }}>
                          <span
                            style={{
                              padding: '3px 8px',
                              borderRadius: 4,
                              fontSize: '0.75rem',
                              fontWeight: 700,
                              background:
                                u.role === 'ADMIN'
                                  ? 'rgba(168, 85, 247, 0.15)'
                                  : u.role === 'ANALYST'
                                  ? 'rgba(0, 212, 255, 0.15)'
                                  : 'rgba(148, 163, 184, 0.15)',
                              color:
                                u.role === 'ADMIN'
                                  ? '#c084fc'
                                  : u.role === 'ANALYST'
                                  ? '#38bdf8'
                                  : '#94a3b8',
                              border:
                                u.role === 'ADMIN'
                                  ? '1px solid rgba(168, 85, 247, 0.3)'
                                  : u.role === 'ANALYST'
                                  ? '1px solid rgba(0, 212, 255, 0.3)'
                                  : '1px solid rgba(148, 163, 184, 0.3)'
                            }}
                          >
                            {u.role}
                          </span>
                        </td>
                        <td style={{ padding: '14px' }}>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: u.is_active ? '#10b981' : '#ef4444', fontSize: '0.78rem', fontWeight: 600 }}>
                            <span style={{ width: 6, height: 6, borderRadius: '50%', background: u.is_active ? '#10b981' : '#ef4444' }} />
                            {u.is_active ? 'ACTIVE' : 'DISABLED'}
                          </span>
                        </td>
                        <td style={{ padding: '14px', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
                          {new Date(u.created_at).toLocaleDateString()}
                        </td>
                        <td style={{ padding: '14px', textAlign: 'right' }}>
                          {u.email !== currentUser?.email && (
                            <button
                              onClick={() => handleDeleteUser(u)}
                              className="btn btn-ghost btn-sm"
                              style={{ color: 'var(--sev-critical)' }}
                            >
                              Revoke Access
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Add User Modal */}
        {showAddModal && (
          <div
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: 'rgba(0, 0, 0, 0.75)',
              backdropFilter: 'blur(8px)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 1000,
              padding: 24
            }}
          >
            <div className="glass-card fade-in" style={{ width: '100%', maxWidth: 460, padding: 32 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                <h3 style={{ margin: 0, fontSize: '1.2rem', color: 'var(--text-primary)' }}>
                  Register New SOC Operator
                </h3>
                <button
                  onClick={() => setShowAddModal(false)}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1.2rem' }}
                >
                  ✕
                </button>
              </div>

              <form onSubmit={handleCreateUser}>
                <div style={{ marginBottom: 16 }}>
                  <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                    OPERATOR EMAIL ADDRESS
                  </label>
                  <input
                    type="email"
                    className="input"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    placeholder="analyst@company.com"
                    required
                  />
                </div>

                <div style={{ marginBottom: 16 }}>
                  <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                    FULL NAME / CALLSIGN
                  </label>
                  <input
                    type="text"
                    className="input"
                    value={formData.full_name}
                    onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                    placeholder="Jane Doe (Security Analyst)"
                  />
                </div>

                <div style={{ marginBottom: 16 }}>
                  <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                    TEMPORARY PASSWORD
                  </label>
                  <input
                    type="password"
                    className="input"
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                    placeholder="At least 8 characters"
                    minLength={8}
                    required
                  />
                </div>

                <div style={{ marginBottom: 24 }}>
                  <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                    RBAC PERMISSION ROLE
                  </label>
                  <select
                    className="input"
                    value={formData.role}
                    onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                    style={{ background: '#020617', color: '#fff' }}
                  >
                    <option value="ANALYST">ANALYST (Alerts, Incidents, IPS Blocking)</option>
                    <option value="ADMIN">ADMIN (Full Access & User Management)</option>
                    <option value="VIEWER">VIEWER (Read-Only Telemetry & Dashboards)</option>
                  </select>
                </div>

                <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
                  <button
                    type="button"
                    onClick={() => setShowAddModal(false)}
                    className="btn btn-ghost"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="btn btn-primary"
                  >
                    {submitting ? 'Creating...' : 'Provision Operator'}
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
