'use client';

import React, { useState, useEffect } from 'react';

export function Spinner() {
  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center', justifyContent: 'center', padding: 32 }}>
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
  return <span className={`badge badge-${s}`}>{severity}</span>;
}

export function StatusBadge({ status }) {
  const s = (status || '').toLowerCase().replace(/ /g, '_');
  return <span className={`badge badge-${s}`}>{status?.replace(/_/g, ' ')}</span>;
}

export function StatCard({ label, value, color, delta, icon }) {
  return (
    <div className="glass-card stat-card" style={{ borderColor: color ? `${color}22` : undefined }}>
      {icon && (
        <div style={{
          position: 'absolute', top: 16, right: 16,
          color: color || 'var(--accent-cyan)',
          opacity: 0.4,
        }}>
          {icon}
        </div>
      )}
      <div className="stat-value" style={{ color: color || 'var(--accent-cyan)' }}>
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
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      )}
      <p style={{ fontSize: '0.875rem' }}>{message}</p>
    </div>
  );
}

export function PageLayout({ children, sidebar }) {
  const [showScrollTop, setShowScrollTop] = useState(false);

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

  return (
    <div className="layout">
      {sidebar}

      {/* Main Content Area with active custom scrollbar */}
      <main className="main-content">
        {/* Page Content */}
        {children}

        {/* Floating Quick Controls (Top button appears when scrolled down) */}
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
