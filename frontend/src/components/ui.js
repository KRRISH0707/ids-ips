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
