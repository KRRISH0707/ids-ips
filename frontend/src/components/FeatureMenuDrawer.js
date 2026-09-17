'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import BrandLogo from './BrandLogo';

export const DASHBOARD_SECTIONS = [
  {
    id: 'section-kpis',
    label: 'Overview & System KPIs',
    desc: 'Real-time open threats, active incidents, critical detections, and quarantined attackers count.',
    icon: '📊',
    badge: 'LIVE METRICS',
  },
  {
    id: 'section-attack-lab',
    label: 'Attack Simulation Laboratory',
    desc: 'Trigger and intercept real-time attack scenarios (Log4Shell, LockBit 3.0, Cobalt Strike, Mirai).',
    icon: '🧪',
    badge: 'INTERACTIVE',
  },
  {
    id: 'section-posture-gauge',
    label: 'Threat Posture Radial Gauge & MTTC',
    desc: 'Dynamic enterprise threat index (0-100) and automated Mean-Time-To-Contain counter.',
    icon: '🛡️',
    badge: 'GAUGE',
  },
  {
    id: 'section-kill-chain',
    label: 'MITRE Cyber Kill Chain Pipeline',
    desc: 'Active intrusion trajectory tracker across Recon, Weaponization, Delivery, Exploitation, and C2.',
    icon: '⛓️',
    badge: 'PIPELINE',
  },
  {
    id: 'section-geo-radar',
    label: 'Geo Threat Origin & Asset Targeting Radar',
    desc: '360° cyber radar tracking geographic origin vectors and targeted infrastructure nodes.',
    icon: '📡',
    badge: 'RADAR',
  },
  {
    id: 'section-ai-engine',
    label: 'AI/ML Multi-Vector Defense & Zero-Day Lab',
    desc: 'Unsupervised Shannon entropy analysis, byte variance, and novel attack testbench.',
    icon: '⚡',
    badge: 'NEURAL ML',
  },
  {
    id: 'section-charts-and-feed',
    label: 'Severity Distribution & WebSocket Live Feed',
    desc: 'Severity breakdown pie chart and real-time sub-second Redis event stream.',
    icon: '🚨',
    badge: 'REAL-TIME',
  },
  {
    id: 'section-recent-alerts',
    label: 'Recent Security Threat Detections',
    desc: 'Tabular DPI dissector of latest open threats, source IPs, and attack categories.',
    icon: '📋',
    badge: 'TABLE',
  },
];

export const PLATFORM_MODULES = [
  { href: '/',             label: 'Threat Command Center', icon: '🚀', desc: 'Main executive SOC dashboard & radar' },
  { href: '/alerts',       label: 'Security Alerts & DPI', icon: '🚨', desc: 'Ingested alerts with full packet inspection' },
  { href: '/incidents',    label: 'Incident Response',     icon: '💼', desc: 'Case lifecycle, digital forensics & tracking' },
  { href: '/ips-actions',  label: 'Active IPS Quarantine', icon: '🛑', desc: 'Firewall IP drop list & containment rules' },
  { href: '/rules',        label: 'Suricata / Snort Rules',icon: '📜', desc: 'Detection rule signatures & ML anomaly rules' },
  { href: '/topology',     label: 'Network Topology',      icon: '🌐', desc: 'Interactive visual node & gateway map' },
  { href: '/playbooks',    label: 'SOAR Playbooks',        icon: '🤖', desc: 'Automated response workflows & execution' },
  { href: '/mitre',        label: 'MITRE ATT&CK Matrix',   icon: '🎯', desc: '13 enterprise tactics & technique coverage' },
  { href: '/threat-intel', label: 'Threat Intelligence',   icon: '🕵️', desc: 'Global IOC reputation check & feeds' },
  { href: '/sensors',      label: 'Sensor Fleet Mesh',     icon: '🖥️', desc: 'Distributed host & network sensor agents' },
  { href: '/audit-logs',   label: 'Compliance Audit Logs', icon: '📋', desc: 'Tamper-evident administrative action log' },
  { href: '/users',        label: 'Users & RBAC Directory',icon: '👥', desc: 'Role-based access control & credentials' },
  { href: '/settings',     label: 'System Settings',       icon: '⚙️', desc: 'Platform configuration, notifications, APIs' },
  { href: '/demo',         label: 'Interactive Sandbox',   icon: '🎮', desc: 'Guided walkthrough & live attack demo' },
];

export default function FeatureMenuDrawer({
  isOpen,
  onClose,
  onSelectSection,
  isSidebarCollapsed,
  onToggleSidebar,
}) {
  const [search, setSearch] = useState('');
  const pathname = usePathname();
  const router = useRouter();

  const isDashboard = pathname === '/';

  const filteredSections = useMemo(() => {
    if (!search.trim()) return DASHBOARD_SECTIONS;
    const q = search.toLowerCase();
    return DASHBOARD_SECTIONS.filter(
      (s) => s.label.toLowerCase().includes(q) || s.desc.toLowerCase().includes(q)
    );
  }, [search]);

  const filteredModules = useMemo(() => {
    if (!search.trim()) return PLATFORM_MODULES;
    const q = search.toLowerCase();
    return PLATFORM_MODULES.filter(
      (m) => m.label.toLowerCase().includes(q) || m.desc.toLowerCase().includes(q)
    );
  }, [search]);

  if (!isOpen) return null;

  const handleSectionClick = (sectionId) => {
    if (isDashboard) {
      if (onSelectSection) {
        onSelectSection(sectionId);
      } else {
        const el = document.getElementById(sectionId);
        if (el) {
          el.scrollIntoView({ behavior: 'smooth', block: 'start' });
          el.classList.add('feature-highlight');
          setTimeout(() => el.classList.remove('feature-highlight'), 2500);
        }
      }
      onClose();
    } else {
      router.push(`/#${sectionId}`);
      onClose();
    }
  };

  const handleModuleClick = (href) => {
    router.push(href);
    onClose();
  };

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(2, 4, 8, 0.75)',
          backdropFilter: 'blur(8px)',
          WebkitBackdropFilter: 'blur(8px)',
          zIndex: 100,
          animation: 'fade-in 0.2s ease',
        }}
      />

      {/* Drawer Container */}
      <div
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          bottom: 0,
          width: 420,
          maxWidth: '92vw',
          background: 'linear-gradient(180deg, rgba(6, 13, 24, 0.98) 0%, rgba(10, 22, 40, 0.98) 100%)',
          borderRight: '1px solid var(--border-bright)',
          boxShadow: '0 0 40px rgba(0, 212, 255, 0.25)',
          zIndex: 101,
          display: 'flex',
          flexDirection: 'column',
          animation: 'slide-in 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
        }}
      >
        {/* Drawer Header */}
        <div style={{ padding: '20px 24px 16px', borderBottom: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <BrandLogo size={34} />
              <div>
                <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 800, letterSpacing: '0.04em' }}>
                  FEATURE COMMAND MENU
                </h2>
                <div style={{ fontSize: '0.68rem', color: 'var(--accent-cyan)', fontWeight: 600, letterSpacing: '0.06em' }}>
                  APEX SENTINEL NAVIGATION & SCROLL SELECTOR
                </div>
              </div>
            </div>
            <button
              onClick={onClose}
              className="btn btn-ghost btn-sm"
              style={{ padding: '4px 10px', fontSize: '1rem', color: 'var(--text-muted)' }}
              title="Close Menu"
            >
              ✕
            </button>
          </div>

          {/* Quick Search */}
          <div style={{ position: 'relative' }}>
            <input
              type="text"
              placeholder="Search features, tools, or jump to section..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 12px 8px 32px',
                background: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid rgba(0, 212, 255, 0.2)',
                borderRadius: 8,
                color: '#fff',
                fontSize: '0.8rem',
                outline: 'none',
              }}
            />
            <span style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', opacity: 0.5, fontSize: '0.8rem' }}>
              🔍
            </span>
          </div>

          {/* View Width & Scroll Quick Controls */}
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button
              onClick={onToggleSidebar}
              className="btn btn-sm"
              style={{
                flex: 1,
                fontSize: '0.72rem',
                padding: '6px 8px',
                background: isSidebarCollapsed ? 'rgba(0, 212, 255, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                border: '1px solid rgba(0, 212, 255, 0.3)',
                color: isSidebarCollapsed ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              }}
            >
              {isSidebarCollapsed ? '▶ Expand Sidebar' : '◀ Maximize Screen (Hide Sidebar)'}
            </button>
            <button
              onClick={() => {
                window.scrollTo({ top: 0, behavior: 'smooth' });
                onClose();
              }}
              className="btn btn-ghost btn-sm"
              style={{ fontSize: '0.72rem', padding: '6px 10px', border: '1px solid rgba(255, 255, 255, 0.1)' }}
            >
              ↑ Top
            </button>
            <button
              onClick={() => {
                window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
                onClose();
              }}
              className="btn btn-ghost btn-sm"
              style={{ fontSize: '0.72rem', padding: '6px 10px', border: '1px solid rgba(255, 255, 255, 0.1)' }}
            >
              ↓ Bottom
            </button>
          </div>
        </div>

        {/* Scrollable Feature List */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>
          {/* Section 1: Dashboard In-Page Features (Quick Scroll) */}
          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700, marginBottom: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>✦ Current Screen Features (Click to Scroll & View)</span>
              <span style={{ color: 'var(--accent-green)', fontSize: '0.65rem' }}>8 SECTIONS</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {filteredSections.map((sec) => (
                <div
                  key={sec.id}
                  onClick={() => handleSectionClick(sec.id)}
                  style={{
                    padding: '10px 14px',
                    borderRadius: 8,
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = 'rgba(0, 212, 255, 0.08)';
                    e.currentTarget.style.borderColor = 'rgba(0, 212, 255, 0.3)';
                    e.currentTarget.style.transform = 'translateX(3px)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)';
                    e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.06)';
                    e.currentTarget.style.transform = 'translateX(0)';
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 700, fontSize: '0.82rem', color: '#f1f5f9' }}>
                      <span>{sec.icon}</span>
                      <span>{sec.label}</span>
                    </div>
                    <span
                      style={{
                        fontSize: '0.6rem',
                        fontWeight: 800,
                        padding: '1px 6px',
                        borderRadius: 4,
                        background: 'rgba(0, 212, 255, 0.12)',
                        color: 'var(--accent-cyan)',
                        border: '1px solid rgba(0, 212, 255, 0.25)',
                      }}
                    >
                      {sec.badge}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.4 }}>
                    {sec.desc}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 2: Full Platform Modules */}
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700, marginBottom: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>✦ Platform Security Modules</span>
              <span style={{ color: 'var(--accent-purple)', fontSize: '0.65rem' }}>14 MODULES</span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {filteredModules.map((mod) => {
                const isActive = pathname === mod.href;
                return (
                  <div
                    key={mod.href}
                    onClick={() => handleModuleClick(mod.href)}
                    style={{
                      padding: '10px 12px',
                      borderRadius: 8,
                      background: isActive ? 'rgba(0, 212, 255, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                      border: isActive ? '1px solid var(--accent-cyan)' : '1px solid rgba(255, 255, 255, 0.06)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                    }}
                    onMouseEnter={(e) => {
                      if (!isActive) {
                        e.currentTarget.style.background = 'rgba(124, 58, 237, 0.1)';
                        e.currentTarget.style.borderColor = 'rgba(124, 58, 237, 0.3)';
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!isActive) {
                        e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)';
                        e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.06)';
                      }
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 700, fontSize: '0.78rem', color: isActive ? 'var(--accent-cyan)' : '#e2e8f0' }}>
                      <span>{mod.icon}</span>
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {mod.label}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.67rem', color: 'var(--text-muted)', marginTop: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {mod.desc}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Drawer Footer */}
        <div style={{ padding: '14px 20px', borderTop: '1px solid var(--border-subtle)', background: 'rgba(0, 0, 0, 0.3)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            Status: <b style={{ color: '#10b981' }}>Mesh Telemetry Synced</b>
          </div>
          <button
            onClick={onClose}
            className="btn btn-primary btn-sm"
            style={{ fontSize: '0.72rem', padding: '4px 12px' }}
          >
            Close Menu
          </button>
        </div>
      </div>
    </>
  );
}
