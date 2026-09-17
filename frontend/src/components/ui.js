'use client';

import React, { useState, useEffect } from 'react';
import FeatureMenuDrawer from './FeatureMenuDrawer';

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
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [featureMenuOpen, setFeatureMenuOpen] = useState(false);
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

  const scrollToBottom = () => {
    window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
  };

  const handleSelectSection = (sectionId) => {
    const el = document.getElementById(sectionId);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      el.classList.add('feature-highlight');
      setTimeout(() => el.classList.remove('feature-highlight'), 2500);
    }
  };

  return (
    <div className="layout">
        {React.isValidElement(sidebar)
          ? React.cloneElement(sidebar, {
              onOpenFeatureMenu: () => setFeatureMenuOpen(true),
              onToggleCollapse: () => setSidebarCollapsed(!sidebarCollapsed),
              isCollapsed: sidebarCollapsed,
            })
          : sidebar}

      {/* Main Content Area */}
      <main className={`main-content ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
        {/* Sticky Top Command Bar featuring prominent Left Menu Button */}
        <div className="top-command-bar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {/* ☰ Left Menu Button */}
            <button
              onClick={() => setFeatureMenuOpen(true)}
              className="btn-menu-trigger"
              title="Open Feature Command Menu & Quick Jump"
            >
              <span style={{ fontSize: '1.1rem', lineHeight: 1 }}>☰</span>
              <span>Features & Menu</span>
            </button>

            {/* Maximize Screen / Sidebar Toggle */}
            <button
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="btn-sidebar-toggle"
              title={sidebarCollapsed ? "Expand Sidebar" : "Hide Sidebar to Maximize Screen"}
            >
              {sidebarCollapsed ? '▶ Show Sidebar' : '◀ Maximize Screen'}
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
              Scroll down to view all widgets & telemetry
            </span>
            <button
              onClick={scrollToBottom}
              className="btn-scroll-jump"
              title="Scroll directly to bottom"
            >
              ↓ Bottom
            </button>
          </div>
        </div>

        {/* Page Content */}
        {children}

        {/* Floating Quick Controls (Always accessible when scrolled) */}
        <div className="floating-scroll-controls">
          {showScrollTop && (
            <button
              onClick={scrollToTop}
              className="floating-btn"
              title="Scroll to Top"
            >
              ↑ Top
            </button>
          )}
          <button
            onClick={() => setFeatureMenuOpen(true)}
            className="floating-btn floating-menu-btn"
            title="Open Feature Menu & Quick Select"
          >
            ☰ Features
          </button>
        </div>
      </main>

      {/* Interactive Feature Command Drawer */}
      <FeatureMenuDrawer
        isOpen={featureMenuOpen}
        onClose={() => setFeatureMenuOpen(false)}
        onSelectSection={handleSelectSection}
        isSidebarCollapsed={sidebarCollapsed}
        onToggleSidebar={() => setSidebarCollapsed(!sidebarCollapsed)}
      />
    </div>
  );
}
