'use client';

import { useState, useEffect, useCallback } from 'react';
import { createPortal } from 'react-dom';
import Sidebar from '@/components/Sidebar';
import BrandLogo from '@/components/BrandLogo';
import { PageLayout, Spinner, EmptyState } from '@/components/ui';
import { api, getUser } from '@/lib/api';

export default function UsersPage() {
  const currentUser = getUser();
  const isAdmin = currentUser?.role === 'ADMIN';

  const [mounted, setMounted] = useState(false);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Visibility states for passwords
  const [revealAll, setRevealAll] = useState(false);
  const [revealedUsers, setRevealedUsers] = useState({});
  const [copiedId, setCopiedId] = useState(null);

  // Modals
  const [showAddModal, setShowAddModal] = useState(false);
  const [createError, setCreateError] = useState('');
  const [resetModalUser, setResetModalUser] = useState(null);
  const [resetPasswordInput, setResetPasswordInput] = useState('');
  const [resetSuccessMessage, setResetSuccessMessage] = useState(null);
  const [submittingReset, setSubmittingReset] = useState(false);

  const [formData, setFormData] = useState({
    email: '',
    full_name: '',
    password: '',
    role: 'ANALYST'
  });
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const fetchUsers = useCallback(async () => {
    if (!isAdmin) {
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      await api.ensureAuth();
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

  const toggleRevealUser = (userId) => {
    setRevealedUsers((prev) => ({
      ...prev,
      [userId]: !prev[userId]
    }));
  };

  const handleCopyPassword = (userId, password) => {
    if (!password || password.includes('••••')) return;
    navigator.clipboard.writeText(password);
    setCopiedId(userId);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const generateRandomPassword = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';
    let result = '';
    for (let i = 0; i < 14; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  };

  const handleOpenAddModal = () => {
    setCreateError('');
    setFormData({
      email: '',
      full_name: '',
      password: generateRandomPassword(),
      role: 'ANALYST'
    });
    setShowAddModal(true);
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setCreateError('');
    try {
      setSubmitting(true);
      await api.createUser(formData);
      setShowAddModal(false);
      setFormData({ email: '', full_name: '', password: '', role: 'ANALYST' });
      await fetchUsers();
    } catch (err) {
      setCreateError(err.message || 'User creation failed');
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenResetModal = (user) => {
    setResetModalUser(user);
    setResetPasswordInput(generateRandomPassword());
    setResetSuccessMessage(null);
  };

  const handleExecutePasswordReset = async (e) => {
    e.preventDefault();
    if (!resetModalUser) return;
    try {
      setSubmittingReset(true);
      const res = await api.resetUserPassword(resetModalUser.id, {
        password: resetPasswordInput.trim() || undefined
      });
      setResetSuccessMessage(`Credentials updated successfully! New password: ${res.new_password}`);
      // Refresh list to update managed password in table
      await fetchUsers();
    } catch (err) {
      alert(`Failed to reset password: ${err.message}`);
    } finally {
      setSubmittingReset(false);
    }
  };

  const handleDeleteUser = async (user) => {
    if (user.id === currentUser?.id) {
      alert('You cannot delete your own active administrator account!');
      return;
    }
    if (!confirm(`Are you sure you want to revoke access and delete credentials for ${user.email} (${user.role})?`)) {
      return;
    }
    try {
      await api.deleteUser(user.id);
      await fetchUsers();
    } catch (err) {
      alert(`Failed to delete user: ${err.message}`);
    }
  };

  // If NOT ADMIN, render strict access-denied barrier
  if (!isAdmin) {
    return (
      <PageLayout sidebar={<Sidebar />}>
        <div className="page-body" style={{ padding: '60px 20px', display: 'flex', justifyContent: 'center' }}>
          <div className="glass-card fade-in" style={{ maxWidth: 580, width: '100%', padding: 40, textAlign: 'center', border: '1px solid rgba(239, 68, 68, 0.4)', boxShadow: '0 0 30px rgba(239, 68, 68, 0.15)' }}>
            <div style={{
              width: 68,
              height: 68,
              borderRadius: '50%',
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.5)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 20px',
              color: '#ef4444'
            }}>
              <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
            <h2 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#f87171', marginBottom: 12 }}>
              ACCESS DENIED — ADMIN CLEARANCE REQUIRED
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', lineHeight: 1.6, marginBottom: 24 }}>
              The <strong>User Fleet & Credential Vault</strong> contains sensitive operator authentication secrets, plaintext credential allocations, and cryptographic hashes. Access is exclusively restricted to verified <strong>ADMIN</strong> operators.
            </p>
            <div style={{ padding: '12px 16px', borderRadius: 8, background: 'rgba(0, 0, 0, 0.4)', border: '1px solid var(--border-subtle)', marginBottom: 24, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              <div>Current Operator: <strong style={{ color: 'var(--text-primary)' }}>{currentUser?.email || 'Unknown Session'}</strong></div>
              <div>Assigned Scope: <strong style={{ color: '#00d4ff' }}>{currentUser?.role || 'VIEWER'}</strong></div>
            </div>
            <a href="/" className="btn btn-primary" style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
                <polyline points="9 22 9 12 15 12 15 22"/>
              </svg>
              Return to SOC Dashboard
            </a>
          </div>
        </div>
      </PageLayout>
    );
  }

  const adminCount = users.filter((u) => u.role === 'ADMIN').length;
  const analystCount = users.filter((u) => u.role === 'ANALYST').length;
  const viewerCount = users.filter((u) => u.role === 'VIEWER').length;

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
            <h1 className="page-title glow-text" style={{ margin: 0 }}>
              User Fleet & Credential Vault
            </h1>
            <span style={{
              padding: '3px 8px',
              borderRadius: 4,
              fontSize: '0.7rem',
              fontWeight: 800,
              background: 'rgba(168, 85, 247, 0.2)',
              color: '#c084fc',
              border: '1px solid rgba(168, 85, 247, 0.5)',
              letterSpacing: '0.05em'
            }}>
              ADMIN CLEARANCE ONLY
            </span>
          </div>
          <p className="page-subtitle">
            Classified security console — Inspect all operator credentials, cryptographic hashes, and configure RBAC policies
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button
            onClick={() => setRevealAll(!revealAll)}
            className="btn btn-ghost"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              border: '1px solid var(--border-normal)',
              color: revealAll ? '#fbbf24' : 'var(--text-secondary)'
            }}
          >
            {revealAll ? (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                  <line x1="1" y1="1" x2="23" y2="23"/>
                </svg>
                Mask All Passwords
              </>
            ) : (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                Reveal All Passwords
              </>
            )}
          </button>

          <button
            onClick={handleOpenAddModal}
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
        </div>
      </div>

      <div className="page-body">
        {/* Security & Stat Counters */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 24 }}>
          <div className="glass-card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 42, height: 42, borderRadius: 8, background: 'rgba(0, 212, 255, 0.15)', border: '1px solid rgba(0, 212, 255, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#00d4ff' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                <circle cx="9" cy="7" r="4"/>
                <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Total Operator Fleet</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)' }}>{users.length}</div>
            </div>
          </div>

          <div className="glass-card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 42, height: 42, borderRadius: 8, background: 'rgba(168, 85, 247, 0.15)', border: '1px solid rgba(168, 85, 247, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#c084fc' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Administrators</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#c084fc' }}>{adminCount}</div>
            </div>
          </div>

          <div className="glass-card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 42, height: 42, borderRadius: 8, background: 'rgba(56, 189, 248, 0.15)', border: '1px solid rgba(56, 189, 248, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#38bdf8' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>SOC Analysts</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#38bdf8' }}>{analystCount}</div>
            </div>
          </div>

          <div className="glass-card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 42, height: 42, borderRadius: 8, background: 'rgba(148, 163, 184, 0.15)', border: '1px solid rgba(148, 163, 184, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#94a3b8' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="16" x2="12" y2="12"/>
                <line x1="12" y1="8" x2="12.01" y2="8"/>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Viewers & Demo</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#94a3b8' }}>{viewerCount}</div>
            </div>
          </div>
        </div>

        {/* User Fleet Table (Admin Only) */}
        <div className="glass-card" style={{ padding: 24, marginBottom: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 10px #10b981' }} />
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                Authorized SOC Operators & Credential Ledger ({users.length})
              </h3>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              🔒 Protected via bcrypt salt & HMAC token authorization
            </div>
          </div>

          {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
              <Spinner />
            </div>
          ) : error ? (
            <div style={{ color: 'var(--sev-critical)', padding: 16 }}>{error}</div>
          ) : users.length === 0 ? (
            <EmptyState message="No operators found" />
          ) : (
            <div className="table-wrapper">
              <table className="data-table" style={{ width: '100%', tableLayout: 'fixed', minWidth: 980, borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                <colgroup>
                  <col style={{ width: '24%' }} />
                  <col style={{ width: '12%' }} />
                  <col style={{ width: '32%' }} />
                  <col style={{ width: '10%' }} />
                  <col style={{ width: '10%' }} />
                  <col style={{ width: '12%' }} />
                </colgroup>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '12px 14px' }}>OPERATOR / EMAIL</th>
                    <th style={{ padding: '12px 14px' }}>ROLE</th>
                    <th style={{ padding: '12px 14px' }}>CREDENTIAL VAULT (ADMIN ONLY)</th>
                    <th style={{ padding: '12px 14px' }}>STATUS</th>
                    <th style={{ padding: '12px 14px' }}>LAST ACTIVITY</th>
                    <th style={{ padding: '12px 14px', textAlign: 'right' }}>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => {
                    const isVisible = revealAll || revealedUsers[u.id];
                    const rawPassword = u.credentials?.password || u.managed_password || '';
                    const displayPassword = isVisible ? (rawPassword || '(No cleartext stored)') : '••••••••••••';
                    const hashPreview = u.credentials?.hash_preview || '';

                    return (
                      <tr key={u.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        {/* Operator / Email */}
                        <td style={{ padding: '14px' }}>
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={u.email}>
                              {u.email}
                            </span>
                            {u.email === currentUser?.email && (
                              <span style={{ fontSize: '0.65rem', padding: '1px 6px', borderRadius: 4, background: 'rgba(0, 212, 255, 0.15)', color: '#00d4ff', border: '1px solid rgba(0, 212, 255, 0.3)', fontWeight: 700, whiteSpace: 'nowrap' }}>
                                You
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={u.full_name || 'Generic SOC Operator'}>
                            {u.full_name || 'Generic SOC Operator'}
                          </div>
                        </td>

                        {/* Role */}
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

                        {/* Credentials Vault (Admin Only) */}
                        <td style={{ padding: '14px' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                            <div style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 8,
                              background: 'rgba(6, 13, 24, 0.8)',
                              padding: '4px 10px',
                              borderRadius: 6,
                              border: '1px solid rgba(0, 212, 255, 0.2)',
                              width: 'fit-content'
                            }}>
                              <span style={{
                                fontFamily: 'JetBrains Mono, monospace',
                                fontSize: '0.84rem',
                                color: isVisible ? '#34d399' : 'var(--text-secondary)',
                                letterSpacing: isVisible ? '0.02em' : '0.2em',
                                minWidth: 105
                              }}>
                                {displayPassword}
                              </span>

                              {/* Toggle eye */}
                              <button
                                type="button"
                                onClick={() => toggleRevealUser(u.id)}
                                title={isVisible ? 'Hide Password' : 'Show Password'}
                                style={{
                                  background: 'none',
                                  border: 'none',
                                  color: isVisible ? '#fbbf24' : 'var(--text-muted)',
                                  cursor: 'pointer',
                                  padding: 2,
                                  display: 'flex',
                                  alignItems: 'center'
                                }}
                              >
                                {isVisible ? (
                                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                                    <line x1="1" y1="1" x2="23" y2="23"/>
                                  </svg>
                                ) : (
                                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                    <circle cx="12" cy="12" r="3"/>
                                  </svg>
                                )}
                              </button>

                              {/* Copy button */}
                              <button
                                type="button"
                                onClick={() => handleCopyPassword(u.id, rawPassword)}
                                title="Copy Password to Clipboard"
                                style={{
                                  background: 'none',
                                  border: 'none',
                                  color: copiedId === u.id ? '#34d399' : 'var(--text-muted)',
                                  cursor: 'pointer',
                                  padding: 2,
                                  display: 'flex',
                                  alignItems: 'center',
                                  fontSize: '0.72rem',
                                  fontWeight: 600
                                }}
                              >
                                {copiedId === u.id ? (
                                  <span style={{ color: '#34d399', fontSize: '0.72rem' }}>Copied!</span>
                                ) : (
                                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                                  </svg>
                                )}
                              </button>
                            </div>

                            {hashPreview && (
                              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                                Hash: <span style={{ color: '#94a3b8' }}>{hashPreview}</span>
                              </div>
                            )}
                          </div>
                        </td>

                        {/* Status */}
                        <td style={{ padding: '14px' }}>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: u.is_active ? '#10b981' : '#ef4444', fontSize: '0.78rem', fontWeight: 600 }}>
                            <span style={{ width: 6, height: 6, borderRadius: '50%', background: u.is_active ? '#10b981' : '#ef4444' }} />
                            {u.is_active ? 'ACTIVE' : 'DISABLED'}
                          </span>
                        </td>

                        {/* Last Activity */}
                        <td style={{ padding: '14px', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
                          <div>{u.last_login ? `Login: ${new Date(u.last_login).toLocaleDateString()}` : 'Never logged in'}</div>
                          <div style={{ fontSize: '0.7rem' }}>Created: {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}</div>
                        </td>

                        {/* Actions */}
                        <td style={{ padding: '14px', textAlign: 'right' }}>
                          <div style={{ display: 'inline-flex', gap: 8 }}>
                            <button
                              onClick={() => handleOpenResetModal(u)}
                              className="btn btn-ghost btn-sm"
                              style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--accent-cyan)' }}
                              title="Rotate or reset password"
                            >
                              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <circle cx="12" cy="12" r="3"/>
                                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                              </svg>
                              Rotate Key
                            </button>

                            {u.email !== currentUser?.email && (
                              <button
                                onClick={() => handleDeleteUser(u)}
                                className="btn btn-ghost btn-sm"
                                style={{ color: 'var(--sev-critical)' }}
                                title="Revoke all access"
                              >
                                Revoke
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Role Matrix Card */}
        <div className="glass-card" style={{ padding: 24, border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent-cyan)' }} />
            <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Two-Layer Enterprise Defense & RBAC Scopes
            </h3>
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: 16 }}>
            Admin operators hold full sovereignty over credentials and cryptographic secrets. Analysts execute operational triage and IPS blocking. Viewers and demo evaluation accounts remain strictly read-only and can never inspect user credentials or configurations.
          </p>

          <div className="table-wrapper" data-horizontal-scroll="true" style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', minWidth: 640, borderCollapse: 'collapse', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '8px 12px' }}>ROLE</th>
                  <th style={{ padding: '8px 12px' }}>CREDENTIAL VAULT</th>
                  <th style={{ padding: '8px 12px' }}>ALERTS & DPI</th>
                  <th style={{ padding: '8px 12px' }}>INCIDENTS</th>
                  <th style={{ padding: '8px 12px' }}>IPS CONTROLS</th>
                  <th style={{ padding: '8px 12px' }}>USER FLEET</th>
                </tr>
              </thead>
              <tbody>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '10px 12px', fontWeight: 700, color: '#a855f7' }}>ADMIN</td>
                  <td style={{ padding: '10px 12px', color: '#10b981' }}>✅ Full Read/Write</td>
                  <td style={{ padding: '10px 12px', color: '#10b981' }}>✅ Full DPI</td>
                  <td style={{ padding: '10px 12px', color: '#10b981' }}>✅ Mitigate</td>
                  <td style={{ padding: '10px 12px', color: '#10b981' }}>✅ Block / Unblock</td>
                  <td style={{ padding: '10px 12px', color: '#10b981' }}>✅ Full Control</td>
                </tr>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '10px 12px', fontWeight: 700, color: '#00d4ff' }}>ANALYST</td>
                  <td style={{ padding: '10px 12px', color: '#ef4444' }}>❌ Zero Access</td>
                  <td style={{ padding: '10px 12px', color: '#10b981' }}>✅ Full DPI</td>
                  <td style={{ padding: '10px 12px', color: '#10b981' }}>✅ Mitigate</td>
                  <td style={{ padding: '10px 12px', color: '#10b981' }}>✅ Block / Unblock</td>
                  <td style={{ padding: '10px 12px', color: '#ef4444' }}>❌ Restricted</td>
                </tr>
                <tr>
                  <td style={{ padding: '10px 12px', fontWeight: 700, color: '#94a3b8' }}>VIEWER</td>
                  <td style={{ padding: '10px 12px', color: '#ef4444' }}>❌ Zero Access</td>
                  <td style={{ padding: '10px 12px', color: '#10b981' }}>✅ Read Telemetry</td>
                  <td style={{ padding: '10px 12px', color: '#f59e0b' }}>👁️ Read-Only</td>
                  <td style={{ padding: '10px 12px', color: '#ef4444' }}>❌ Restricted</td>
                  <td style={{ padding: '10px 12px', color: '#ef4444' }}>❌ Restricted</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Rotate / Reset Password Modal (Centered Viewport Portal, styled like Login Page) */}
        {resetModalUser && mounted && typeof document !== 'undefined' && createPortal(
          <div
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              width: '100vw',
              height: '100vh',
              background: 'rgba(2, 4, 8, 0.85)',
              backdropFilter: 'blur(12px)',
              WebkitBackdropFilter: 'blur(12px)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 999999,
              padding: 24,
              overflowY: 'auto',
              margin: 0
            }}
            onClick={(e) => {
              if (e.target === e.currentTarget) setResetModalUser(null);
            }}
          >
            {/* Ambient glow like login page */}
            <div style={{
              position: 'fixed',
              top: '35%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              width: 550,
              height: 350,
              background: 'radial-gradient(ellipse, rgba(0,212,255,0.09) 0%, transparent 70%)',
              pointerEvents: 'none',
              zIndex: 0,
            }}/>

            <div
              className="hud-card fade-in"
              style={{
                width: '100%',
                maxWidth: 460,
                padding: '38px 34px',
                boxShadow: '0 20px 50px rgba(0, 0, 0, 0.7), 0 0 30px rgba(0, 212, 255, 0.15)',
                position: 'relative',
                zIndex: 1,
                maxHeight: '92vh',
                overflowY: 'auto'
              }}
            >
              {/* Close Button */}
              <button
                onClick={() => setResetModalUser(null)}
                type="button"
                style={{
                  position: 'absolute',
                  top: 16,
                  right: 16,
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: 6,
                  width: 30,
                  height: 30,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  fontSize: '1rem',
                  transition: 'all 0.2s',
                  zIndex: 2,
                }}
                title="Close"
              >
                ✕
              </button>

              {/* Header styled like Login Page */}
              <div style={{ textAlign: 'center', marginBottom: 24 }}>
                <BrandLogo size={52} style={{ margin: '0 auto 12px' }} />
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 10px', borderRadius: 20, background: 'rgba(0, 212, 255, 0.08)', border: '1px solid rgba(0, 212, 255, 0.25)', marginBottom: 8 }}>
                  <span className="live-dot" style={{ width: 6, height: 6 }} />
                  <span style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--accent-cyan)', letterSpacing: '0.06em' }}>CREDENTIAL SECURITY</span>
                </div>
                <h2 style={{ fontSize: '1.4rem', fontWeight: 900, letterSpacing: '0.04em', margin: 0 }}>
                  <span className="glow-gradient">ROTATE OPERATOR KEY</span>
                </h2>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4, letterSpacing: '0.04em' }}>
                  TARGET: <strong style={{ color: 'var(--accent-cyan)' }}>{resetModalUser.email}</strong>
                </p>
              </div>

              {resetSuccessMessage ? (
                <div>
                  <div style={{ padding: '16px', borderRadius: 8, background: 'rgba(16, 185, 129, 0.15)', border: '1px solid #10b981', color: '#6ee7b7', fontSize: '0.88rem', marginBottom: 20, textAlign: 'center' }}>
                    <div style={{ fontWeight: 700, marginBottom: 6 }}>Key Successfully Rotated!</div>
                    <div style={{ wordBreak: 'break-all' }}>{resetSuccessMessage}</div>
                  </div>
                  <button
                    onClick={() => setResetModalUser(null)}
                    className="btn btn-primary"
                    style={{ width: '100%', padding: '12px' }}
                  >
                    Done
                  </button>
                </div>
              ) : (
                <form onSubmit={handleExecutePasswordReset}>
                  <div style={{ marginBottom: 20 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <label style={{ fontSize: '0.78rem', fontWeight: 500, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
                        NEW SECURE ACCESS KEY
                      </label>
                      <button
                        type="button"
                        onClick={() => setResetPasswordInput(generateRandomPassword())}
                        style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', fontSize: '0.72rem', cursor: 'pointer', textDecoration: 'underline', fontWeight: 600 }}
                      >
                        🎲 Auto-Gen
                      </button>
                    </div>
                    <input
                      type="text"
                      className="input"
                      value={resetPasswordInput}
                      onChange={(e) => setResetPasswordInput(e.target.value)}
                      placeholder="Enter custom or generated password"
                      required
                      minLength={8}
                      style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.9rem' }}
                    />
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 6 }}>
                      Immediately re-hashed with bcrypt (12 rounds) across all nodes.
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end', marginTop: 24 }}>
                    <button
                      type="button"
                      onClick={() => setResetModalUser(null)}
                      className="btn btn-ghost"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={submittingReset}
                      className="btn btn-primary"
                    >
                      {submittingReset ? 'Updating...' : 'Save & Rotate Key'}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>,
          document.body
        )}

        {/* Add User Modal (Centered Viewport Portal, styled like Login Page) */}
        {showAddModal && mounted && typeof document !== 'undefined' && createPortal(
          <div
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              width: '100vw',
              height: '100vh',
              background: 'rgba(2, 4, 8, 0.85)',
              backdropFilter: 'blur(12px)',
              WebkitBackdropFilter: 'blur(12px)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 999999,
              padding: 24,
              overflowY: 'auto',
              margin: 0
            }}
            onClick={(e) => {
              if (e.target === e.currentTarget) setShowAddModal(false);
            }}
          >
            {/* Ambient glow like login page */}
            <div style={{
              position: 'fixed',
              top: '35%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              width: 550,
              height: 350,
              background: 'radial-gradient(ellipse, rgba(0,212,255,0.09) 0%, transparent 70%)',
              pointerEvents: 'none',
              zIndex: 0,
            }}/>

            <div
              className="hud-card fade-in"
              style={{
                width: '100%',
                maxWidth: 460,
                padding: '38px 34px',
                boxShadow: '0 20px 50px rgba(0, 0, 0, 0.7), 0 0 30px rgba(0, 212, 255, 0.15)',
                position: 'relative',
                zIndex: 1,
                maxHeight: '92vh',
                overflowY: 'auto'
              }}
            >
              {/* Close Button */}
              <button
                onClick={() => setShowAddModal(false)}
                type="button"
                style={{
                  position: 'absolute',
                  top: 16,
                  right: 16,
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: 6,
                  width: 30,
                  height: 30,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  fontSize: '1rem',
                  transition: 'all 0.2s',
                  zIndex: 2,
                }}
                title="Close"
              >
                ✕
              </button>

              {/* Header styled just like Login Page */}
              <div style={{ textAlign: 'center', marginBottom: 24 }}>
                <BrandLogo size={56} style={{ margin: '0 auto 14px' }} />
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 10px', borderRadius: 20, background: 'rgba(0, 212, 255, 0.08)', border: '1px solid rgba(0, 212, 255, 0.25)', marginBottom: 8 }}>
                  <span className="live-dot" style={{ width: 6, height: 6 }} />
                  <span style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--accent-cyan)', letterSpacing: '0.06em' }}>SOC OPERATOR ONBOARDING</span>
                </div>
                <h2 style={{ fontSize: '1.45rem', fontWeight: 900, letterSpacing: '0.04em', margin: 0 }}>
                  <span className="glow-gradient">REGISTER SOC OPERATOR</span>
                </h2>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4, letterSpacing: '0.04em' }}>
                  PROVISION ACCESS KEY & ROLE-BASED ACCESS CONTROL
                </p>
              </div>

              {createError && (
                <div style={{
                  background: 'rgba(239, 68, 68, 0.12)',
                  border: '1px solid var(--accent-red)',
                  color: '#fca5a5',
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.85rem',
                  marginBottom: 18,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                }}>
                  <span>⚠️</span>
                  <span>{createError}</span>
                </div>
              )}

              <form onSubmit={handleCreateUser}>
                <div style={{ marginBottom: 16 }}>
                  <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6, letterSpacing: '0.04em' }}>
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
                  <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6, letterSpacing: '0.04em' }}>
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
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                    <label style={{ fontSize: '0.78rem', fontWeight: 500, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
                      INITIAL PROVISIONED PASSWORD
                    </label>
                    <button
                      type="button"
                      onClick={() => setFormData({ ...formData, password: generateRandomPassword() })}
                      style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', fontSize: '0.72rem', cursor: 'pointer', textDecoration: 'underline', fontWeight: 600 }}
                    >
                      🎲 Auto-Generate
                    </button>
                  </div>
                  <input
                    type="text"
                    className="input"
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                    placeholder="At least 8 characters"
                    minLength={8}
                    required
                    style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.9rem' }}
                  />
                </div>

                <div style={{ marginBottom: 24 }}>
                  <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6, letterSpacing: '0.04em' }}>
                    RBAC PERMISSION ROLE
                  </label>
                  <select
                    className="input"
                    value={formData.role}
                    onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                    style={{ background: '#050b14', color: '#fff' }}
                  >
                    <option value="ANALYST">ANALYST — DPI Alerts, Incident Triage, IPS Block/Mitigate</option>
                    <option value="ADMIN">ADMIN — Full System Access, Operator Provisioning & Audit</option>
                    <option value="VIEWER">VIEWER — Read-Only Telemetry & Threat Surveillance</option>
                  </select>
                </div>

                <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end', marginTop: 8 }}>
                  <button
                    type="button"
                    onClick={() => setShowAddModal(false)}
                    className="btn btn-ghost"
                    style={{ padding: '10px 18px' }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="btn btn-primary"
                    style={{ padding: '10px 20px' }}
                  >
                    {submitting ? 'Provisioning...' : 'Provision Operator'}
                  </button>
                </div>
              </form>
            </div>
          </div>,
          document.body
        )}
      </div>
    </PageLayout>
  );
}
