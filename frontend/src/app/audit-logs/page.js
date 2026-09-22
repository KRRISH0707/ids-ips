'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, Spinner, EmptyState, Pagination } from '@/components/ui';
import { api } from '@/lib/api';
import { useOnLiveEvent } from '@/lib/useLiveFeed';
import { exportToCSV, formatRelativeTime } from '@/lib/utils';

function formatAuditDetails(log) {
  const { action, details, resource_id } = log;

  let d = details;
  if (typeof details === 'string') {
    try {
      d = JSON.parse(details);
    } catch {
      d = { note: details };
    }
  }

  const data = d || {};

  switch (action) {
    case 'LOGIN_SUCCESS':
      return `Authenticated successfully via ${data.auth_type || 'management console'} ${data.role ? `[Role: ${data.role}]` : ''}`;

    case 'LOGIN_FAILED':
      return `Failed authentication attempt (${data.reason || 'invalid credentials'})`;

    case 'USER_CREATED':
      return `Created user account '${data.email}' with role '${data.role || 'ANALYST'}'`;

    case 'USER_UPDATED':
      return `Updated profile for user '${data.email || (resource_id && resource_id.length === 36 ? `ID: ${resource_id.slice(0, 8)}...` : resource_id)}' ${data.role ? `[Role: ${data.role}]` : ''}${data.is_active !== undefined ? ` [Active: ${data.is_active}]` : ''}`;

    case 'USER_DELETED': {
      const targetUser = data.deleted_user_email || data.email;
      return targetUser
        ? `Deleted user account '${targetUser}' (${data.deleted_user_role || 'user'})`
        : `Deleted user account (ID: ${resource_id && resource_id.length === 36 ? `${resource_id.slice(0, 8)}...` : resource_id || '—'})`;
    }

    case 'ALERT_STATUS_CHANGED':
      return `Updated alert lifecycle status to '${data.new_status || data.status || 'RESOLVED'}'${data.signature ? ` (${data.signature})` : ''}`;

    case 'ALERTS_BATCH_RESOLVED':
      return `Bulk resolved ${data.count || 'open'} threat alerts -> ${data.target_status || 'RESOLVED'}`;

    case 'MACHINE_ISOLATED':
      return `Quarantined host machine ${data.hostname || data.ip || resource_id} (Network Isolated)`;

    case 'MACHINE_RESTORED':
      return `Restored host machine ${data.hostname || data.ip || resource_id} to active network`;

    case 'IP_BLOCKED':
    case 'IPS_IP_BLOCKED':
      return `Quarantined IP ${data.ip || resource_id} — Reason: ${data.reason || 'Automated IPS trigger'}`;

    case 'IP_UNBLOCKED':
    case 'IPS_IP_UNBLOCKED':
      return `Unblocked IP ${data.ip || resource_id} — Reason: ${data.reason || 'Manual analyst action'}`;

    case 'RULE_CREATED':
      return `Created detection rule '${data.name || data.rule_name}' [Type: ${data.rule_type || 'SIG'}]`;

    case 'RULE_UPDATED':
      return `Modified rule '${data.rule_name || data.name || resource_id}' (${Object.keys(data).filter(k => k !== 'rule_name' && k !== 'name').join(', ')})`;

    case 'RULE_TOGGLED':
      return `Toggled detection rule '${data.rule_name || resource_id}' -> ${data.enabled ? 'ENABLED' : 'DISABLED'}`;

    case 'RULE_DELETED':
      return `Removed detection rule '${data.rule_name || data.name || resource_id}'`;

    case 'SENSOR_REGISTERED':
      return `Registered network sensor '${data.name}' (${data.type || 'edge_node'})`;

    case 'SENSOR_UPDATED':
      return `Updated sensor parameters for '${data.name || resource_id}'`;

    case 'SENSOR_DELETED':
      return `Decommissioned network sensor '${data.name || resource_id}'`;

    case 'INCIDENT_CREATED':
      return `Created security incident '${data.title}' [Severity: ${data.severity || 'HIGH'}]`;

    case 'INCIDENT_STATUS_CHANGED':
      return `Updated incident status to '${data.new_status || data.status}'`;

    case 'PLAYBOOK_CREATED':
      return `Created SOAR playbook '${data.name}' (Trigger: ${data.trigger})`;

    case 'PLAYBOOK_EXECUTED':
      return `Executed SOAR playbook on target ${data.target || 'system'}`;

    case 'THREAT_INDICATOR_ADDED':
      return `Added threat indicator [${data.ioc_type}]: ${data.value} (${data.threat_type})`;

    case 'SETTINGS_UPDATED':
      return `Updated platform sensitivity thresholds & IPS configuration`;

    default:
      if (data && typeof data === 'object' && Object.keys(data).length > 0) {
        return Object.entries(data)
          .map(([k, v]) => `${k.replace(/_/g, ' ')}: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
          .join(' | ');
      }
      return 'Action logged successfully';
  }
}

import { useTimeRange } from '@/context/TimeRangeContext';

export default function AuditLogsPage() {
  const { days, dateSpanText } = useTimeRange();
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchActor, setSearchActor] = useState('');
  const [searchAction, setSearchAction] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // Reset pagination to page 1 whenever filters or timeframe change
  useEffect(() => {
    setCurrentPage(1);
  }, [days, searchActor, searchAction, pageSize]);

  const fetchLogs = useCallback(async (showSpinner = true) => {
    try {
      if (showSpinner) setLoading(true);
      const res = await api.getAuditLogs({
        days: days || undefined,
        limit: 1000,
        actor: searchActor || undefined,
        action: searchAction || undefined
      });
      setLogs(res?.items || res?.data || (Array.isArray(res) ? res : []));
      setError(null);
    } catch (err) {
      if (showSpinner) setError(err.message || 'Failed to fetch audit logs');
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, [days, searchActor, searchAction]);

  // Paginated slice
  const paginatedLogs = logs.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  useEffect(() => {
    fetchLogs(true);
  }, [fetchLogs]);

  // Real-time synchronization: automatically prepend or refresh on every attack or administrative action
  useOnLiveEvent((event) => {
    if (event.type === 'AUDIT_LOG' || (event.action && event.actor)) {
      setLogs((prev) => {
        if (event.id && prev.some((l) => l.id === event.id)) return prev;
        return [
          {
            id: event.id || `audit-${Date.now()}`,
            action: event.action,
            actor: event.actor || 'System',
            actor_id: event.actor_id,
            resource: event.resource || 'security',
            resource_id: event.resource_id,
            details: event.details,
            source_ip: event.source_ip,
            created_at: event.created_at || new Date().toISOString(),
            _isNew: true,
          },
          ...prev,
        ];
      });
    } else {
      // Incoming attack, incident, or IPS action -> refresh audit trail in background
      fetchLogs(false);
    }
  });

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title glow-text">Audit Logs</h1>
          <p className="page-subtitle">Immutable compliance audit trail of user actions, policy updates, and mitigations</p>
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            type="text"
            className="input"
            placeholder="Filter by actor/user..."
            value={searchActor}
            onChange={e => setSearchActor(e.target.value)}
            style={{ width: 180, fontSize: '0.82rem', padding: '6px 12px' }}
          />
          <input
            type="text"
            className="input"
            placeholder="Filter by action..."
            value={searchAction}
            onChange={e => setSearchAction(e.target.value)}
            style={{ width: 180, fontSize: '0.82rem', padding: '6px 12px' }}
          />
          {(searchActor || searchAction) && (
            <button className="btn btn-ghost btn-sm" onClick={() => { setSearchActor(''); setSearchAction(''); }}>Clear</button>
          )}
          <button
            className="btn-export"
            onClick={() => exportToCSV(
              logs,
              ['created_at','actor','action','resource','source_ip'],
              ['Timestamp','Actor','Action','Resource','Source IP'],
              `audit_logs_${new Date().toISOString().slice(0,10)}.csv`
            )}
          >
            ⬇ Export CSV
          </button>
          <button className="btn btn-primary btn-sm" onClick={fetchLogs}>
            Refresh
          </button>
        </div>
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
          <div className="glass-card table-wrapper" data-horizontal-scroll="true" style={{ overflowX: 'auto', padding: 0 }}>
            <table className="data-table" style={{ width: '100%', tableLayout: 'fixed', minWidth: '960px' }}>
              <thead>
                <tr>
                  <th style={{ width: '175px' }}>Timestamp</th>
                  <th style={{ width: '200px' }}>Actor / User</th>
                  <th style={{ width: '185px' }}>Action</th>
                  <th style={{ width: '110px' }}>Resource</th>
                  <th style={{ width: '120px' }}>Source IP</th>
                  <th style={{ width: 'auto' }}>Details</th>
                </tr>
              </thead>
              <tbody>
                {paginatedLogs.map((log) => (
                  <tr key={log.id}>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {(() => { const { relative, absolute } = formatRelativeTime(log.created_at); return <span className="rel-time" title={absolute}>{relative}</span>; })()}
                    </td>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)', wordBreak: 'break-word', fontSize: '0.82rem' }}>
                      {log.actor || 'System'}
                    </td>
                    <td>
                      <span
                        className="badge"
                        style={{
                          background: 'rgba(59, 130, 246, 0.15)',
                          color: '#60a5fa',
                          border: '1px solid rgba(59, 130, 246, 0.3)',
                          fontSize: '0.72rem',
                          fontWeight: 600,
                          display: 'inline-block',
                          whiteSpace: 'nowrap'
                        }}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{log.resource || '—'}</td>
                    <td style={{ fontSize: '0.8rem', fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                      {log.source_ip || '127.0.0.1'}
                    </td>
                    <td style={{ fontSize: '0.83rem', color: '#e2e8f0', fontWeight: 500, wordBreak: 'break-word', lineHeight: '1.45' }}>
                      {formatAuditDetails(log)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Controls */}
        <Pagination
          currentPage={currentPage}
          pageSize={pageSize}
          totalItems={logs.length}
          label="audit log records"
          loading={loading}
          onPageChange={(page) => setCurrentPage(page)}
          onPageSizeChange={(newSize) => {
            setPageSize(newSize);
            setCurrentPage(1);
          }}
        />
      </div>
    </PageLayout>
  );
}
