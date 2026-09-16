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
      setLogs(res.data || []);
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
    <Sidebar>
      <PageLayout
        title="Audit Logs"
        subtitle="Immutable compliance audit trail of user actions, policy updates, and mitigations"
        actions={
          <button className="btn btn-primary btn-sm" onClick={fetchLogs}>
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
        ) : logs.length === 0 ? (
          <EmptyState
            title="No Audit Records Found"
            description="System activity logs will appear here as administrative actions occur."
          />
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Actor / User</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>IP Address</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{log.username || 'System'}</td>
                    <td>
                      <span
                        className="badge"
                        style={{
                          background: 'rgba(59, 130, 246, 0.1)',
                          color: 'var(--accent-blue)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.75rem'
                        }}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.85rem' }}>{log.resource || 'N/A'}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{log.ip_address || '127.0.0.1'}</td>
                    <td style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                      {typeof log.details === 'object' ? JSON.stringify(log.details) : log.details || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PageLayout>
    </Sidebar>
  );
}
