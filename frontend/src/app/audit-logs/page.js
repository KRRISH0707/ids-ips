'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';

export default function AuditLogsPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchLogs = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getAuditLogs();
      setLogs(res?.items || res?.data || (Array.isArray(res) ? res : []));
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to fetch audit logs');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Audit Logs</h1>
          <p className="page-subtitle">Immutable compliance audit trail of user actions, policy updates, and mitigations</p>
        </div>
        <button className="btn btn-primary btn-sm" onClick={fetchLogs}>
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
        ) : logs.length === 0 ? (
          <EmptyState message="No audit records found" />
        ) : (
          <div className="glass-card">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Actor / User</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Source IP</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{log.actor || 'System'}</td>
                    <td>
                      <span
                        className="badge"
                        style={{
                          background: 'rgba(59, 130, 246, 0.1)',
                          color: 'var(--accent-blue)',
                          fontSize: '0.75rem'
                        }}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.85rem' }}>{log.resource || '—'}</td>
                    <td style={{ fontSize: '0.8rem', fontFamily: 'monospace' }}>{log.source_ip || '127.0.0.1'}</td>
                    <td style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                      {typeof log.details === 'object' ? JSON.stringify(log.details) : log.details || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </PageLayout>
  );
}
