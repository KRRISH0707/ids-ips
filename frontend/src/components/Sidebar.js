'use client';

import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { clearToken, getUser } from '@/lib/api';
import { useOnLiveEvent } from '@/lib/useLiveFeed';
import BrandLogo from './BrandLogo';

// Module-level persistent scroll memory across page unmounts/remounts
let savedSidebarScroll = 0;

const NAV_SECTIONS = [
  {
    title: 'Command & Operations',
    items: [
      { href: '/',             label: 'Command Center', icon: IconGrid },
      { href: '/topology',     label: 'Network Mesh',   icon: IconTopology },
      { href: '/playbooks',    label: 'SOAR Playbooks', icon: IconPlaybook },
    ],
  },
  {
    title: 'Threat Intelligence',
    items: [
      { href: '/mitre',        label: 'MITRE ATT&CK',   icon: IconMitre },
      { href: '/threat-intel', label: 'Threat Intel',   icon: IconIntel },
    ],
  },
  {
    title: 'Detection & Response',
    items: [
      { href: '/alerts',       label: 'Alerts Queue',   icon: IconAlert },
      { href: '/incidents',    label: 'Incidents',      icon: IconIncident },
      { href: '/ips-actions',  label: 'IPS Quarantine', icon: IconShield, analystOrAdmin: true },
      { href: '/sensors',      label: 'Sensors & Probes', icon: IconSensor },
      { href: '/rules',        label: 'Detection Rules', icon: IconRules },
    ],
  },
  {
    title: 'Administration',
    items: [
      { href: '/audit-logs',   label: 'Audit Logs',     icon: IconAudit, adminOnly: true },
      { href: '/users',        label: 'Users & RBAC',   icon: IconUsers, adminOnly: true },
      { href: '/settings',     label: 'Settings',       icon: IconSettings, adminOnly: true },
    ],
  },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const user = getUser();
  const navRef = useRef(null);

  const [filterText, setFilterText] = useState('');
  const [newAlertCount, setNewAlertCount] = useState(0);
  const [blockedFlash, setBlockedFlash] = useState(false);
  const [threatFlash, setThreatFlash] = useState(false);

  // Restore and maintain sidebar scroll position on navigation so it never jumps to the top
  useEffect(() => {
    if (navRef.current) {
      let saved = savedSidebarScroll;
      if (!saved) {
        try {
          saved = Number(sessionStorage.getItem('apex_sidebar_scroll') || 0);
        } catch {}
      }
      if (saved) {
        navRef.current.scrollTop = saved;
      }

      // Smoothly ensure the currently active navigation item is in view
      const activeEl = navRef.current.querySelector('.nav-item.active');
      if (activeEl) {
        activeEl.scrollIntoView({ block: 'nearest', behavior: 'instant' });
      }
    }
  }, [pathname]);

  const handleNavScroll = (e) => {
    savedSidebarScroll = e.currentTarget.scrollTop;
    try {
      sessionStorage.setItem('apex_sidebar_scroll', String(savedSidebarScroll));
    } catch {}
  };

  const handleLinkClick = () => {
    if (navRef.current) {
      savedSidebarScroll = navRef.current.scrollTop;
      try {
        sessionStorage.setItem('apex_sidebar_scroll', String(savedSidebarScroll));
      } catch {}
    }
  };

  // Real-time telemetry pulses
  useOnLiveEvent((event) => {
    if (event.signature || event.src_ip) {
      setNewAlertCount((prev) => prev + 1);
      setThreatFlash(true);
      setTimeout(() => setThreatFlash(false), 4000);

      if (event.autonomous_mitigation?.prevented || event.status === 'AUTO_BLOCKED') {
        setBlockedFlash(true);
        setTimeout(() => setBlockedFlash(false), 5000);
      }
    }
  });

  const handleLogout = () => {
    clearToken();
    router.push('/login');
  };

  return (
    <aside className="sidebar">
      {/* Compact Brand Header */}
      <div style={{ padding: '12px 14px 8px', borderBottom: '1px solid var(--border-normal)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <BrandLogo size={28} />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: '0.88rem', fontWeight: 900, letterSpacing: '0.03em', display: 'flex', alignItems: 'center', gap: 6 }}>
                <span className="glow-gradient text-truncate">APEX SENTINEL</span>
              </div>
              <div style={{ fontSize: '0.58rem', color: 'var(--accent-cyan)', letterSpacing: '0.07em', fontWeight: 700 }}>
                AUTONOMOUS DEFENSE
              </div>
            </div>
          </div>

          <span
            style={{
              fontSize: '0.62rem',
              fontWeight: 700,
              padding: '2px 6px',
              borderRadius: 4,
              background: threatFlash ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.12)',
              border: `1px solid ${threatFlash ? 'rgba(239, 68, 68, 0.5)' : 'rgba(16, 185, 129, 0.3)'}`,
              color: threatFlash ? '#f87171' : '#34d399',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4
            }}
          >
            <span style={{ width: 5, height: 5, borderRadius: '50%', background: threatFlash ? '#ef4444' : '#10b981' }} />
            {threatFlash ? 'ALERT' : 'LIVE'}
          </span>
        </div>

        {/* Global Search Trigger (Ctrl+K) */}
        <button
          className="global-search-trigger"
          onClick={() => typeof window !== 'undefined' && window.openGlobalSearch?.()}
          style={{ width: '100%', marginTop: 8, justifyContent: 'space-between' }}
          title="Open global search (Ctrl+K)"
        >
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span>🔍</span>
            <span>Search platform...</span>
          </span>
          <kbd style={{ fontSize: '0.62rem', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 3, padding: '1px 4px', fontFamily: 'monospace', color: 'var(--text-muted)' }}>⌃K</kbd>
        </button>

        {/* Compact Module Filter Input */}
        <div style={{ marginTop: 6 }}>
          <input
            type="text"
            className="input"
            placeholder="Filter modules..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            style={{
              padding: '4px 8px',
              fontSize: '0.72rem',
              borderRadius: 6,
              background: 'rgba(6, 13, 24, 0.6)',
              borderColor: 'rgba(0, 212, 255, 0.15)',
              width: '100%'
            }}
          />
        </div>
      </div>


      {/* Nav with Section Grouping & Scroll Memory */}
      <nav
        ref={navRef}
        onScroll={handleNavScroll}
        style={{ flex: 1, padding: '4px 0', overflowY: 'auto' }}
      >
        {NAV_SECTIONS.map((section, sIdx) => {
          const visibleItems = section.items.filter((item) => {
            if (item.adminOnly && user?.role !== 'ADMIN') return false;
            if (item.analystOrAdmin && user?.role === 'VIEWER') return false;
            if (filterText.trim() && !item.label.toLowerCase().includes(filterText.toLowerCase())) return false;
            return true;
          });

          if (visibleItems.length === 0) return null;

          return (
            <div key={sIdx} style={{ marginBottom: 2 }}>
              <div className="sidebar-section-header">
                {section.title}
              </div>
              {visibleItems.map(({ href, label, icon: Icon }) => {
                const isAlert = href === '/alerts';
                const isIps = href === '/ips-actions';
                const isActive = pathname === href;

                return (
                  <Link
                    key={href}
                    href={href}
                    scroll={false}
                    onClick={handleLinkClick}
                    className={`nav-item${isActive ? ' active' : ''}`}
                    style={{ minWidth: 0 }}
                  >
                    <Icon />
                    <span className="text-truncate" style={{ flex: 1 }} title={label}>
                      {label}
                    </span>
                    {isAlert && newAlertCount > 0 && (
                      <span style={{
                        fontSize: '0.62rem',
                        fontWeight: 800,
                        padding: '1px 5px',
                        borderRadius: 8,
                        background: 'rgba(239, 68, 68, 0.25)',
                        border: '1px solid #ef4444',
                        color: '#fca5a5',
                        boxShadow: '0 0 8px rgba(239, 68, 68, 0.3)',
                        flexShrink: 0,
                      }}>
                        +{newAlertCount}
                      </span>
                    )}
                    {isIps && blockedFlash && (
                      <span style={{
                        fontSize: '0.62rem',
                        fontWeight: 800,
                        padding: '1px 5px',
                        borderRadius: 8,
                        background: 'rgba(16, 185, 129, 0.25)',
                        border: '1px solid #10b981',
                        color: '#6ee7b7',
                        flexShrink: 0,
                      }}>
                        BLOCKED
                      </span>
                    )}
                  </Link>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* Compact User Footer */}
      <div style={{ borderTop: '1px solid var(--border-normal)', padding: '8px 12px', background: 'rgba(4, 9, 18, 0.6)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <div style={{
            width: 26, height: 26, borderRadius: '50%',
            background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.3), rgba(139, 92, 246, 0.3))',
            border: '1px solid var(--border-normal)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-cyan)'
          }}>
            {user?.email?.[0]?.toUpperCase() || 'U'}
          </div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={user?.email}>
              {user?.email || 'Unknown'}
            </div>
            <div style={{ fontSize: '0.62rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>{user?.role || 'ANALYST'}</div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 6 }}>
          <Link
            href="/demo"
            scroll={false}
            onClick={handleLinkClick}
            className="btn btn-ghost btn-sm"
            style={{
              flex: 1,
              padding: '3px 6px',
              fontSize: '0.7rem',
              justifyContent: 'center',
              background: 'rgba(0, 212, 255, 0.08)',
              border: '1px solid rgba(0, 212, 255, 0.25)',
              color: 'var(--accent-cyan)',
              textDecoration: 'none'
            }}
          >
            <IconPlay /> Sandbox
          </Link>
          <button
            className="btn btn-ghost btn-sm"
            style={{ padding: '3px 8px', fontSize: '0.7rem' }}
            onClick={handleLogout}
            title="Sign out"
          >
            <IconLogout />
          </button>
        </div>
      </div>
    </aside>
  );
}

function IconPlay() {
  return <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>;
}

// ── Icons ─────────────────────────────────────────────────────────────────────
function IconGrid() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>;
}
function IconAlert() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
}
function IconIncident() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>;
}
function IconSensor() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M5 12.55a11 11 0 0114.08 0"/><path d="M1.42 9a16 16 0 0121.16 0"/><path d="M8.53 16.11a6 6 0 016.95 0"/><circle cx="12" cy="20" r="1"/></svg>;
}
function IconRules() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>;
}
function IconShield() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
}
function IconAudit() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>;
}
function IconLogout() {
  return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>;
}
function IconTopology() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>;
}
function IconPlaybook() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>;
}
function IconMitre() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M9 21V9"/></svg>;
}
function IconIntel() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 2a10 10 0 100 20 10 10 0 000-20z"/><path d="M12 6v6l4 2"/><circle cx="12" cy="12" r="2"/></svg>;
}
function IconUsers() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>;
}
function IconSettings() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>;
}
