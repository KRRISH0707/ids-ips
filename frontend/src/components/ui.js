'use client';

import React, { useState, useEffect } from 'react';

export function Spinner() {
  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center', justifyContent: 'center', padding: 36 }}>
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="loading-dot"
          style={{ animationDelay: `${i * 0.2}s` }}
        />
      ))}
    </div>
  );
}

export function SeverityBadge({ severity }) {
  const s = (severity || '').toLowerCase();
  return (
    <span className={`badge badge-${s}`}>
      <span className="badge-dot" />
      <span>{severity}</span>
    </span>
  );
}

export function StatusBadge({ status }) {
  const s = (status || '').toLowerCase().replace(/ /g, '_');
  return (
    <span className={`badge badge-${s}`}>
      <span className="badge-dot" />
      <span>{status?.replace(/_/g, ' ')}</span>
    </span>
  );
}

export function StatCard({ label, value, color, delta, icon }) {
  const activeColor = color || 'var(--accent-cyan)';
  return (
    <div
      className="glass-card stat-card"
      style={{
        borderTop: `3px solid ${activeColor}`,
        borderColor: `${activeColor}33`,
      }}
    >
      {icon && (
        <div style={{
          position: 'absolute', top: 16, right: 16,
          color: activeColor,
          opacity: 0.5,
          filter: `drop-shadow(0 0 6px ${activeColor})`
        }}>
          {icon}
        </div>
      )}
      <div className="stat-value" style={{ color: activeColor }}>
        {value ?? '—'}
      </div>
      <div className="stat-label">{label}</div>
      {delta && <div className="stat-delta">{delta}</div>}
    </div>
  );
}

export function EmptyState({ message = 'No data found', icon }) {
  return (
    <div className="empty-state">
      {icon || (
        <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      )}
      <p style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-secondary)' }}>{message}</p>
    </div>
  );
}

import { useRouter } from 'next/navigation';
import { getToken, getUser } from '@/lib/api';
import { TimeRangeProvider, useTimeRange, TimeRangeSelector } from '@/context/TimeRangeContext';

export { TimeRangeProvider, useTimeRange, TimeRangeSelector };

function PageLayoutContent({ children, sidebar }) {
  const router = useRouter();
  const [authorized, setAuthorized] = useState(() => {
    if (typeof window === 'undefined') return true;
    const token = getToken();
    const user = getUser();
    return !!(token && user);
  });
  const [showScrollTop, setShowScrollTop] = useState(false);

  useEffect(() => {
    const token = getToken();
    const user = getUser();
    if (!token || !user) {
      setAuthorized(false);
      router.replace('/login');
    } else {
      setAuthorized(true);
    }
  }, [router]);

  useEffect(() => {
    const handleScroll = () => {
      setShowScrollTop(window.scrollY > 250);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  if (!authorized) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--bg-void)'
      }}>
        <Spinner />
      </div>
    );
  }

  return (
    <div className="layout bg-grid">
      {sidebar}

      {/* Main Content Area */}
      <main className="main-content fade-in">
        {/* Global Telemetry Time-Window Bar */}
        <div style={{
          display: 'flex',
          justifyContent: 'flex-end',
          alignItems: 'center',
          marginBottom: 16,
          padding: '2px 0'
        }}>
          <TimeRangeSelector />
        </div>

        {/* Page Content */}
        {children}

        {/* Floating Controls */}
        {showScrollTop && (
          <div className="floating-scroll-controls">
            <button
              onClick={scrollToTop}
              className="floating-btn"
              title="Scroll to Top"
            >
              ↑ Top
            </button>
          </div>
        )}
      </main>
    </div>
  );
}

export function PageLayout(props) {
  return <PageLayoutContent {...props} />;
}

export function Pagination({
  currentPage = 1,
  pageSize = 25,
  totalItems = 0,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [15, 25, 50, 100],
  loading = false,
  label = 'records',
  alwaysShow = true,
}) {
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  if (totalItems === 0) return null;
  if (!alwaysShow && totalPages <= 1) return null;

  const start = totalItems === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const end = Math.min(currentPage * pageSize, totalItems);

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      flexWrap: 'wrap',
      gap: 12,
      padding: '12px 18px',
      background: 'rgba(6, 13, 24, 0.88)',
      border: '1px solid var(--border-subtle)',
      borderRadius: 10,
      marginTop: 16,
      boxShadow: '0 4px 20px rgba(0, 0, 0, 0.4)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
        <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
          Showing <span style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>{start}–{end}</span> of{' '}
          <span style={{ color: '#f8fafc', fontWeight: 700 }}>{totalItems}</span> {label}
          {totalPages > 1 && (
            <span style={{ color: 'var(--text-muted)' }}> • Page {currentPage} of {totalPages}</span>
          )}
        </div>

        {onPageSizeChange && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            <span>Per page:</span>
            <select
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              className="select"
              style={{
                padding: '2px 8px',
                fontSize: '0.76rem',
                width: 'auto',
                fontFamily: 'JetBrains Mono, monospace'
              }}
            >
              {pageSizeOptions.map((opt) => (
                <option key={opt} value={opt}>{opt}</option>
              ))}
            </select>
          </div>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <button
          onClick={() => onPageChange && onPageChange(currentPage - 1)}
          disabled={currentPage <= 1 || loading}
          className="btn"
          style={{
            padding: '6px 14px',
            fontSize: '0.8rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            opacity: currentPage <= 1 ? 0.35 : 1,
            cursor: currentPage <= 1 ? 'not-allowed' : 'pointer'
          }}
          title={currentPage <= 1 ? 'First page reached' : 'Go to previous page'}
        >
          ← Previous
        </button>

        <span style={{
          padding: '4px 12px',
          background: 'rgba(0, 212, 255, 0.1)',
          border: '1px solid rgba(0, 212, 255, 0.3)',
          borderRadius: 6,
          color: 'var(--accent-cyan)',
          fontSize: '0.8rem',
          fontWeight: 700,
          fontFamily: 'JetBrains Mono, monospace'
        }}>
          {currentPage} / {totalPages}
        </span>

        <button
          onClick={() => onPageChange && onPageChange(currentPage + 1)}
          disabled={currentPage >= totalPages || loading}
          className="btn"
          style={{
            padding: '6px 14px',
            fontSize: '0.8rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            opacity: currentPage >= totalPages ? 0.35 : 1,
            cursor: currentPage >= totalPages ? 'not-allowed' : 'pointer'
          }}
          title={currentPage >= totalPages ? 'Last page reached' : 'Go to next page'}
        >
          Next →
        </button>
      </div>
    </div>
  );
}

