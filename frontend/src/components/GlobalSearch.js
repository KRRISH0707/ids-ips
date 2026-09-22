'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';

/**
 * Global Command Palette / Search (Cmd+K / Ctrl+K)
 *
 * Searches across Alerts, Incidents, IPS Blocks, and Detection Rules simultaneously.
 * Navigate with ↑↓ arrows, press Enter to go, Escape to close.
 */

const QUICK_NAV = [
  { label: 'Command Center', path: '/', icon: '🏠', category: 'Navigation' },
  { label: 'Alerts Queue', path: '/alerts', icon: '🚨', category: 'Navigation' },
  { label: 'Security Incidents', path: '/incidents', icon: '🔴', category: 'Navigation' },
  { label: 'IPS Quarantine', path: '/ips-actions', icon: '🛡️', category: 'Navigation' },
  { label: 'SOAR Playbooks', path: '/playbooks', icon: '⚙️', category: 'Navigation' },
  { label: 'MITRE ATT&CK', path: '/mitre', icon: '🗺️', category: 'Navigation' },
  { label: 'Threat Intelligence', path: '/threat-intel', icon: '🌐', category: 'Navigation' },
  { label: 'Network Topology', path: '/topology', icon: '📡', category: 'Navigation' },
  { label: 'Sensors & Probes', path: '/sensors', icon: '📊', category: 'Navigation' },
  { label: 'Detection Rules', path: '/rules', icon: '📋', category: 'Navigation' },
  { label: 'Audit Logs', path: '/audit-logs', icon: '📝', category: 'Navigation' },
  { label: 'Users & RBAC', path: '/users', icon: '👤', category: 'Navigation' },
  { label: 'System Settings', path: '/settings', icon: '⚙️', category: 'Navigation' },
];

export function GlobalSearch() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [isSearching, setIsSearching] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef(null);
  const router = useRouter();
  const debounceRef = useRef(null);

  // Open/Close with Cmd+K or Ctrl+K
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Expose as global function
  useEffect(() => {
    window.openGlobalSearch = () => setOpen(true);
    return () => delete window.openGlobalSearch;
  }, []);

  // Focus input when opened
  useEffect(() => {
    if (open) {
      setQuery('');
      setResults(QUICK_NAV);
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 60);
    }
  }, [open]);

  const doSearch = useCallback(async (q) => {
    if (!q.trim()) {
      setResults(QUICK_NAV);
      setIsSearching(false);
      return;
    }

    setIsSearching(true);
    const queryLower = q.toLowerCase();

    // Always include nav quick matches
    const navMatches = QUICK_NAV.filter(
      (n) => n.label.toLowerCase().includes(queryLower)
    );

    try {
      // Parallel API searches
      const [alertsRes, incidentsRes] = await Promise.allSettled([
        api.getAlerts({ limit: 5, skip: 0 }),
        api.getIncidents({ limit: 5 }),
      ]);

      const alertItems = (alertsRes.status === 'fulfilled' ? alertsRes.value?.items || [] : [])
        .filter((a) =>
          (a.signature || '').toLowerCase().includes(queryLower) ||
          (a.src_ip || '').includes(q) ||
          (a.dst_ip || '').includes(q)
        )
        .slice(0, 4)
        .map((a) => ({
          label: a.signature || 'Unknown Alert',
          sublabel: `${a.src_ip || '?'} → ${a.dst_ip || '?'} · ${a.severity}`,
          path: `/alerts`,
          icon: a.severity === 'CRITICAL' ? '🚨' : a.severity === 'HIGH' ? '⚠️' : '🔔',
          category: 'Alerts',
          severity: a.severity,
        }));

      const incidentItems = (incidentsRes.status === 'fulfilled' ? incidentsRes.value?.items || [] : [])
        .filter((i) =>
          (i.title || '').toLowerCase().includes(queryLower) ||
          (i.description || '').toLowerCase().includes(queryLower)
        )
        .slice(0, 3)
        .map((i) => ({
          label: i.title || 'Unknown Incident',
          sublabel: `${i.severity} · ${i.status}`,
          path: `/incidents`,
          icon: '🔴',
          category: 'Incidents',
        }));

      const combined = [...navMatches, ...alertItems, ...incidentItems];
      setResults(combined.length > 0 ? combined : navMatches);
    } catch {
      setResults(navMatches);
    } finally {
      setIsSearching(false);
    }
  }, []);

  // Debounced search
  useEffect(() => {
    if (!open) return;
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => doSearch(query), 300);
    return () => clearTimeout(debounceRef.current);
  }, [query, open, doSearch]);

  // Keyboard navigation
  const handleKeyDown = (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter') {
      const item = results[selectedIndex];
      if (item) navigate(item);
    }
  };

  const navigate = (item) => {
    router.push(item.path);
    setOpen(false);
  };

  if (!open) return null;

  // Group results by category
  const grouped = results.reduce((acc, item) => {
    const cat = item.category || 'Navigation';
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(item);
    return acc;
  }, {});

  let flatIndex = 0;

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 100000,
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        paddingTop: '10vh',
        background: 'rgba(0,0,0,0.7)',
        backdropFilter: 'blur(8px)',
      }}
      onClick={() => setOpen(false)}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 620,
          background: 'linear-gradient(135deg, rgba(6,13,24,0.98), rgba(10,20,36,0.98))',
          border: '1px solid rgba(0, 212, 255, 0.25)',
          borderRadius: 14,
          boxShadow: '0 32px 80px rgba(0,0,0,0.8), 0 0 40px rgba(0,212,255,0.12)',
          overflow: 'hidden',
          animation: 'toastSlideIn 0.2s ease',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
          <span style={{ fontSize: '1.1rem', opacity: 0.5 }}>🔍</span>
          <input
            ref={inputRef}
            type="text"
            placeholder="Search alerts, incidents, IPs, rules... (Ctrl+K)"
            value={query}
            onChange={(e) => { setQuery(e.target.value); setSelectedIndex(0); }}
            onKeyDown={handleKeyDown}
            style={{
              flex: 1,
              background: 'none',
              border: 'none',
              outline: 'none',
              fontSize: '1rem',
              color: '#f8fafc',
              fontFamily: 'inherit',
            }}
          />
          {isSearching && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Searching…</span>
          )}
          <kbd style={{
            fontSize: '0.7rem',
            background: 'rgba(255,255,255,0.08)',
            border: '1px solid rgba(255,255,255,0.15)',
            borderRadius: 4,
            padding: '2px 6px',
            color: 'var(--text-muted)',
            fontFamily: 'monospace',
          }}>ESC</kbd>
        </div>

        {/* Results */}
        <div style={{ maxHeight: 420, overflowY: 'auto', padding: '8px 0' }}>
          {results.length === 0 ? (
            <div style={{ padding: '24px 20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              No results found for &ldquo;{query}&rdquo;
            </div>
          ) : (
            Object.entries(grouped).map(([category, items]) => (
              <div key={category}>
                <div style={{
                  padding: '6px 20px 4px',
                  fontSize: '0.68rem',
                  fontWeight: 700,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                }}>
                  {category}
                </div>
                {items.map((item) => {
                  const currentIdx = flatIndex++;
                  const isSelected = currentIdx === selectedIndex;
                  return (
                    <div
                      key={`${category}-${currentIdx}`}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 12,
                        padding: '9px 20px',
                        cursor: 'pointer',
                        background: isSelected ? 'rgba(0, 212, 255, 0.08)' : 'transparent',
                        borderLeft: isSelected ? '2px solid #00d4ff' : '2px solid transparent',
                        transition: 'all 0.1s ease',
                      }}
                      onClick={() => navigate(item)}
                      onMouseEnter={() => setSelectedIndex(currentIdx)}
                    >
                      <span style={{ fontSize: '1rem', width: 22, textAlign: 'center' }}>{item.icon}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{
                          fontSize: '0.875rem',
                          fontWeight: 600,
                          color: isSelected ? '#00d4ff' : '#e2e8f0',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}>
                          {item.label}
                        </div>
                        {item.sublabel && (
                          <div style={{
                            fontSize: '0.75rem',
                            color: 'var(--text-muted)',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            fontFamily: 'monospace',
                          }}>
                            {item.sublabel}
                          </div>
                        )}
                      </div>
                      {item.severity && (
                        <span style={{
                          fontSize: '0.65rem',
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: 4,
                          background: item.severity === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : item.severity === 'HIGH' ? 'rgba(249,115,22,0.2)' : 'rgba(245,158,11,0.2)',
                          color: item.severity === 'CRITICAL' ? '#fca5a5' : item.severity === 'HIGH' ? '#fdba74' : '#fcd34d',
                        }}>
                          {item.severity}
                        </span>
                      )}
                      {isSelected && (
                        <kbd style={{ fontSize: '0.65rem', color: 'var(--text-muted)', background: 'rgba(255,255,255,0.08)', padding: '2px 5px', borderRadius: 3, border: '1px solid rgba(255,255,255,0.12)', fontFamily: 'monospace' }}>↵</kbd>
                      )}
                    </div>
                  );
                })}
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div style={{
          padding: '8px 20px',
          borderTop: '1px solid rgba(255,255,255,0.06)',
          display: 'flex',
          gap: 16,
          fontSize: '0.7rem',
          color: 'var(--text-muted)',
        }}>
          <span><kbd style={{ fontFamily: 'monospace', background: 'rgba(255,255,255,0.07)', padding: '1px 4px', borderRadius: 3 }}>↑↓</kbd> navigate</span>
          <span><kbd style={{ fontFamily: 'monospace', background: 'rgba(255,255,255,0.07)', padding: '1px 4px', borderRadius: 3 }}>↵</kbd> open</span>
          <span><kbd style={{ fontFamily: 'monospace', background: 'rgba(255,255,255,0.07)', padding: '1px 4px', borderRadius: 3 }}>ESC</kbd> close</span>
          <span style={{ marginLeft: 'auto' }}>Apex Sentinel Global Search</span>
        </div>
      </div>
    </div>
  );
}
