'use client';

import React, { useState, useEffect, useRef } from 'react';
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
  const [menuOpen, setMenuOpen] = useState(false);
  const [showScrollTop, setShowScrollTop] = useState(false);
  const mainRef = useRef(null);

  // Mouse horizontal drag-to-scroll state
  const [isDragging, setIsDragging] = useState(false);
  const [startX, setStartX] = useState(0);
  const [scrollLeftPos, setScrollLeftPos] = useState(0);

  useEffect(() => {
    const handleScroll = () => {
      setShowScrollTop(window.scrollY > 250);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Mouse drag-to-scroll handlers for horizontal panning
  const handleMouseDown = (e) => {
    if (e.button !== 0) return; // only left click
    if (['INPUT', 'BUTTON', 'A', 'SELECT', 'TEXTAREA'].includes(e.target.tagName)) return;
    if (e.target.closest('button, a, input, select, textarea, .data-table, .recharts-wrapper')) return;
    
    setIsDragging(true);
    setStartX(e.pageX - (mainRef.current?.offsetLeft || 0));
    setScrollLeftPos(mainRef.current?.scrollLeft || 0);
  };

  const handleMouseLeave = () => {
    setIsDragging(false);
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleMouseMove = (e) => {
    if (!isDragging || !mainRef.current) return;
    e.preventDefault();
    const x = e.pageX - (mainRef.current.offsetLeft || 0);
    const walk = (x - startX) * 1.5;
    mainRef.current.scrollLeft = scrollLeftPos - walk;
  };

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
            onOpenMenu: () => setMenuOpen(true),
            onOpenFeatureMenu: () => setMenuOpen(true),
          })
        : sidebar}

      {/* Main Content Area with unrestricted mouse horizontal & vertical scroll */}
      <main
        ref={mainRef}
        className={`main-content ${isDragging ? 'mouse-grabbing' : ''}`}
        onMouseDown={handleMouseDown}
        onMouseLeave={handleMouseLeave}
        onMouseUp={handleMouseUp}
        onMouseMove={handleMouseMove}
      >
        {/* Sticky Top Command Bar featuring prominent Left Menu Button */}
        <div className="top-command-bar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {/* ☰ Left Menu Button */}
            <button
              onClick={() => setMenuOpen(true)}
              className="btn-menu-trigger"
              title="Open Menu to access Dashboard, Alerts, Rules & all platform features"
            >
              <span style={{ fontSize: '1.15rem', lineHeight: 1 }}>☰</span>
              <span>Menu</span>
            </button>

            {/* Mouse Scroll Indicator */}
            <div className="scroll-indicator-hint" title="Scroll horizontally left and right using mouse wheel, drag, or horizontal scrollbar">
              <span style={{ color: 'var(--accent-cyan)' }}>⇄</span>
              <span>Mouse Scroll: Left ↔ Right</span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
              Scroll down or left/right to view all info
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
            onClick={() => setMenuOpen(true)}
            className="floating-btn floating-menu-btn"
            title="Open Menu"
          >
            ☰ Menu
          </button>
        </div>
      </main>

      {/* Interactive Platform Menu Drawer */}
      <FeatureMenuDrawer
        isOpen={menuOpen}
        onClose={() => setMenuOpen(false)}
        onSelectSection={handleSelectSection}
      />
    </div>
  );
}
