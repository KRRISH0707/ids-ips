'use client';

import { useState, useMemo } from 'react';
import { ATTACK_SCENARIOS, ATTACK_CATEGORIES } from '@/lib/attackScenarios';

/**
 * AttackTaxonomyPanel Component
 * Interactive, searchable 100-attack threat matrix and taxonomy ledger.
 * Displays real-time session interception telemetry, MITRE ATT&CK mappings,
 * autonomous mitigation states, and direct one-click simulation hooks.
 */
export default function AttackTaxonomyPanel({
  onTriggerAttack = () => {},
  onOpenDossier = () => {},
  triggeredAttackKeys = new Set(),
  lastTriggeredKey = null,
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedStatus, setSelectedStatus] = useState('ALL'); // 'ALL' | 'INTERCEPTED' | 'PENDING'
  const [pageSize, setPageSize] = useState(25);
  const [currentPage, setCurrentPage] = useState(1);

  // Category counts for badges
  const categoryCounts = useMemo(() => {
    const counts = { ALL: ATTACK_SCENARIOS.length };
    ATTACK_SCENARIOS.forEach((atk) => {
      counts[atk.categoryGroup] = (counts[atk.categoryGroup] || 0) + 1;
    });
    return counts;
  }, []);

  // Filtered list
  const filteredAttacks = useMemo(() => {
    return ATTACK_SCENARIOS.filter((atk) => {
      // Category filter
      if (selectedCategory !== 'ALL' && atk.categoryGroup !== selectedCategory) {
        return false;
      }
      // Severity filter
      if (selectedSeverity !== 'ALL' && atk.badge !== selectedSeverity) {
        return false;
      }
      // Intercept status filter
      const isIntercepted = triggeredAttackKeys.has(atk.key);
      if (selectedStatus === 'INTERCEPTED' && !isIntercepted) return false;
      if (selectedStatus === 'PENDING' && isIntercepted) return false;

      // Text search
      if (searchTerm.trim()) {
        const query = searchTerm.toLowerCase();
        const matchName = atk.name.toLowerCase().includes(query);
        const matchShort = atk.shortName.toLowerCase().includes(query);
        const matchKey = atk.key.toLowerCase().includes(query);
        const matchCve = (atk.cve || '').toLowerCase().includes(query);
        const matchActor = (atk.actor || '').toLowerCase().includes(query);
        const matchProto = (atk.protocol || '').toLowerCase().includes(query);
        return matchName || matchShort || matchKey || matchCve || matchActor || matchProto;
      }
      return true;
    });
  }, [searchTerm, selectedCategory, selectedSeverity, selectedStatus, triggeredAttackKeys]);

  const totalPages = Math.ceil(filteredAttacks.length / pageSize) || 1;
  const paginatedAttacks = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredAttacks.slice(start, start + pageSize);
  }, [filteredAttacks, currentPage, pageSize]);

  const interceptedCount = useMemo(() => {
    let count = 0;
    ATTACK_SCENARIOS.forEach((atk) => {
      if (triggeredAttackKeys.has(atk.key)) count++;
    });
    return count;
  }, [triggeredAttackKeys]);

  const coveragePercent = Math.round((interceptedCount / ATTACK_SCENARIOS.length) * 100);

  return (
    <div
      className="glass-card"
      style={{
        padding: 24,
        marginBottom: 24,
        border: '1px solid rgba(0, 212, 255, 0.25)',
        position: 'relative',
        background: 'linear-gradient(180deg, rgba(8, 14, 24, 0.85) 0%, rgba(4, 8, 16, 0.95) 100%)',
      }}
    >
      {/* Header with Live Taxonomy Metrics */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20, flexWrap: 'wrap', gap: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: '1.25rem' }}>🧬</span>
            <h3 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '0.02em' }}>
              Full 100-Attack Threat Taxonomy & Interception Matrix
            </h3>
            <span
              style={{
                fontSize: '0.68rem',
                fontWeight: 800,
                padding: '2px 8px',
                borderRadius: 4,
                background: 'rgba(0, 212, 255, 0.15)',
                color: 'var(--accent-cyan)',
                border: '1px solid rgba(0, 212, 255, 0.35)',
                fontFamily: 'JetBrains Mono, monospace',
              }}
            >
              101 VECTORS INDEXED
            </span>
          </div>
          <p style={{ margin: '6px 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Complete enterprise taxonomy across Malware, Network, Credential, Web/API, Exploitation & Post-Compromise. Every vector is equipped with autonomous IPS containment rules.
          </p>
        </div>

        {/* Real-time Session Coverage Widget */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 16,
            background: 'rgba(0, 0, 0, 0.4)',
            padding: '10px 18px',
            borderRadius: 8,
            border: '1px solid rgba(255, 255, 255, 0.08)',
          }}
        >
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Audit Coverage
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 2 }}>
              <span style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--accent-cyan)', fontFamily: 'JetBrains Mono' }}>
                {interceptedCount}
              </span>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                / {ATTACK_SCENARIOS.length}
              </span>
              <span
                style={{
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  color: coveragePercent > 0 ? 'var(--accent-green)' : 'var(--text-muted)',
                  marginLeft: 4,
                }}
              >
                ({coveragePercent}%)
              </span>
            </div>
          </div>

          {/* Mini progress bar */}
          <div style={{ width: 90, height: 6, background: 'rgba(255, 255, 255, 0.1)', borderRadius: 3, overflow: 'hidden' }}>
            <div
              style={{
                width: `${coveragePercent}%`,
                height: '100%',
                background: 'linear-gradient(90deg, #00d4ff 0%, #10b981 100%)',
                transition: 'width 0.4s ease',
              }}
            />
          </div>
        </div>
      </div>

      {/* Category Tabs with dynamic vector counts */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, overflowX: 'auto', paddingBottom: 6 }}>
        {ATTACK_CATEGORIES.map((cat) => {
          const isActive = selectedCategory === cat.id;
          const count = categoryCounts[cat.id] || 0;
          return (
            <button
              key={cat.id}
              onClick={() => {
                setSelectedCategory(cat.id);
                setCurrentPage(1);
              }}
              style={{
                padding: '6px 14px',
                borderRadius: 6,
                fontSize: '0.75rem',
                fontWeight: isActive ? 800 : 500,
                background: isActive
                  ? 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)'
                  : 'rgba(255, 255, 255, 0.04)',
                border: isActive ? '1px solid transparent' : '1px solid rgba(255, 255, 255, 0.08)',
                color: isActive ? '#fff' : 'var(--text-muted)',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'all 0.2s ease',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <span>{cat.name}</span>
              <span
                style={{
                  fontSize: '0.65rem',
                  background: isActive ? 'rgba(0, 0, 0, 0.3)' : 'rgba(255, 255, 255, 0.08)',
                  padding: '1px 6px',
                  borderRadius: 10,
                  fontWeight: 700,
                }}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Filter & Search Toolbar */}
      <div
        style={{
          display: 'flex',
          gap: 12,
          marginBottom: 16,
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        {/* Search input */}
        <div style={{ flex: '1 1 280px', position: 'relative' }}>
          <input
            type="text"
            placeholder="Search 100 attacks by name, CVE, signature, port, actor..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            style={{
              width: '100%',
              padding: '8px 12px 8px 34px',
              borderRadius: 6,
              background: 'rgba(255, 255, 255, 0.04)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              color: '#fff',
              fontSize: '0.8rem',
              outline: 'none',
              transition: 'border 0.2s',
            }}
          />
          <span style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            🔍
          </span>
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              style={{
                position: 'absolute',
                right: 8,
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                fontSize: '0.8rem',
              }}
            >
              ✕
            </button>
          )}
        </div>

        {/* Severity filter dropdown */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select
            value={selectedSeverity}
            onChange={(e) => {
              setSelectedSeverity(e.target.value);
              setCurrentPage(1);
            }}
            style={{
              padding: '7px 12px',
              borderRadius: 6,
              background: 'rgba(10, 18, 30, 0.8)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              color: 'var(--text-secondary)',
              fontSize: '0.75rem',
              cursor: 'pointer',
              outline: 'none',
            }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Interception Status Filter */}
          <select
            value={selectedStatus}
            onChange={(e) => {
              setSelectedStatus(e.target.value);
              setCurrentPage(1);
            }}
            style={{
              padding: '7px 12px',
              borderRadius: 6,
              background: 'rgba(10, 18, 30, 0.8)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              color: 'var(--text-secondary)',
              fontSize: '0.75rem',
              cursor: 'pointer',
              outline: 'none',
            }}
          >
            <option value="ALL">All Statuses</option>
            <option value="INTERCEPTED">🛡️ Intercepted ({interceptedCount})</option>
            <option value="PENDING">⏳ Pending Audit ({ATTACK_SCENARIOS.length - interceptedCount})</option>
          </select>

          {/* Rows per page selector */}
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setCurrentPage(1);
            }}
            style={{
              padding: '7px 10px',
              borderRadius: 6,
              background: 'rgba(10, 18, 30, 0.8)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              color: 'var(--text-secondary)',
              fontSize: '0.75rem',
              cursor: 'pointer',
              outline: 'none',
            }}
          >
            <option value={15}>15 rows</option>
            <option value={25}>25 rows</option>
            <option value={50}>50 rows</option>
            <option value={101}>All 101 rows</option>
          </select>
        </div>
      </div>

      {/* 100-Row Cyber Threat Ledger Table */}
      <div
        className="table-wrapper"
        data-horizontal-scroll="true"
        style={{
          overflowX: 'auto',
          borderRadius: 8,
          border: '1px solid rgba(255, 255, 255, 0.08)',
          background: 'rgba(4, 9, 18, 0.6)',
        }}
      >
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
          <thead>
            <tr style={{ background: 'rgba(0, 212, 255, 0.06)', borderBottom: '1px solid rgba(0, 212, 255, 0.2)' }}>
              <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 700, width: 44 }}>#</th>
              <th style={{ padding: '10px 14px', color: 'var(--text-primary)', fontWeight: 700 }}>Attack / Threat Vector</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-primary)', fontWeight: 700 }}>Category & Kill Chain</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-primary)', fontWeight: 700 }}>Severity & CVSS</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-primary)', fontWeight: 700 }}>Target Asset</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-primary)', fontWeight: 700 }}>Session Status</th>
              <th style={{ padding: '10px 14px', color: 'var(--text-primary)', fontWeight: 700, textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {paginatedAttacks.map((atk, index) => {
              const globalIndex = (currentPage - 1) * pageSize + index + 1;
              const isIntercepted = triggeredAttackKeys.has(atk.key);
              const isJustTriggered = lastTriggeredKey === atk.key;
              const isCritical = atk.badge === 'CRITICAL';

              return (
                <tr
                  key={atk.id}
                  style={{
                    borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                    background: isJustTriggered
                      ? 'rgba(0, 212, 255, 0.12)'
                      : isIntercepted
                      ? 'rgba(16, 185, 129, 0.03)'
                      : 'transparent',
                    transition: 'background 0.25s ease',
                  }}
                >
                  {/* Row number */}
                  <td style={{ padding: '10px 12px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono', fontSize: '0.72rem' }}>
                    {globalIndex.toString().padStart(2, '0')}
                  </td>

                  {/* Attack Name & Signature */}
                  <td style={{ padding: '10px 14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.82rem' }}>
                        {atk.name}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 2, fontFamily: 'JetBrains Mono' }}>
                      <span style={{ color: 'var(--accent-cyan)' }}>{atk.key}</span> · {atk.actor} · {atk.cve}
                    </div>
                  </td>

                  {/* Category & Kill Chain */}
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                      {atk.categoryGroup.replace('_', '/')}
                    </div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 2 }}>
                      Phase 0{atk.killChainStage + 1}: {atk.killChainName}
                    </div>
                  </td>

                  {/* Severity & CVSS */}
                  <td style={{ padding: '10px 12px' }}>
                    <span
                      style={{
                        display: 'inline-block',
                        fontSize: '0.65rem',
                        fontWeight: 800,
                        padding: '2px 6px',
                        borderRadius: 3,
                        background: isCritical ? 'rgba(239, 68, 68, 0.2)' : 'rgba(249, 115, 22, 0.2)',
                        color: isCritical ? '#ef4444' : '#f97316',
                        border: `1px solid ${isCritical ? 'rgba(239, 68, 68, 0.4)' : 'rgba(249, 115, 22, 0.4)'}`,
                      }}
                    >
                      {atk.badge} · {atk.cvss.split(' ')[0]}
                    </span>
                  </td>

                  {/* Target Asset & Port */}
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ fontSize: '0.75rem', fontFamily: 'JetBrains Mono', color: 'var(--text-secondary)' }}>
                      {atk.targetAsset.split(' ')[0]}
                    </div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                      Port {atk.targetPort} ({atk.protocol})
                    </div>
                  </td>

                  {/* Live Session Status */}
                  <td style={{ padding: '10px 12px' }}>
                    {isIntercepted ? (
                      <span
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 5,
                          fontSize: '0.68rem',
                          fontWeight: 700,
                          padding: '3px 8px',
                          borderRadius: 4,
                          background: 'rgba(16, 185, 129, 0.15)',
                          color: '#10b981',
                          border: '1px solid rgba(16, 185, 129, 0.35)',
                          boxShadow: '0 0 10px rgba(16, 185, 129, 0.2)',
                        }}
                      >
                        <span style={{ fontSize: '0.7rem' }}>🛡️</span>
                        QUARANTINED ({atk.mttc})
                      </span>
                    ) : (
                      <span
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                          fontSize: '0.68rem',
                          fontWeight: 600,
                          padding: '3px 8px',
                          borderRadius: 4,
                          background: 'rgba(255, 255, 255, 0.04)',
                          color: 'var(--text-muted)',
                          border: '1px solid rgba(255, 255, 255, 0.08)',
                        }}
                      >
                        <span>⏳</span>
                        PENDING AUDIT
                      </span>
                    )}
                  </td>

                  {/* Action Buttons */}
                  <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                      <button
                        onClick={() => onTriggerAttack(atk)}
                        title="Simulate Attack & Test Autonomous IPS Severance"
                        style={{
                          padding: '4px 10px',
                          borderRadius: 5,
                          background: isJustTriggered
                            ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)'
                            : 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)',
                          border: 'none',
                          color: '#fff',
                          fontWeight: 700,
                          fontSize: '0.72rem',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 4,
                          transition: 'all 0.2s',
                        }}
                      >
                        <span>⚡</span>
                        {isJustTriggered ? 'Severed!' : 'Trigger'}
                      </button>

                      <button
                        onClick={() => onOpenDossier(atk)}
                        title="Inspect Attack Vectors, Hex Payloads, and MITRE Dossier"
                        style={{
                          padding: '4px 8px',
                          borderRadius: 5,
                          background: 'rgba(255, 255, 255, 0.05)',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          color: 'var(--text-secondary)',
                          fontSize: '0.72rem',
                          cursor: 'pointer',
                          transition: 'all 0.2s',
                        }}
                      >
                        🔍 Dossier
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}

            {paginatedAttacks.length === 0 && (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '32px 16px', color: 'var(--text-muted)' }}>
                  No attack scenarios match the active search or category filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginTop: 14,
          flexWrap: 'wrap',
          gap: 12,
          fontSize: '0.78rem',
          color: 'var(--text-muted)',
        }}
      >
        <div>
          Showing {(currentPage - 1) * pageSize + 1} - {Math.min(currentPage * pageSize, filteredAttacks.length)} of {filteredAttacks.length} vectors
        </div>

        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <button
            disabled={currentPage === 1}
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            style={{
              padding: '4px 10px',
              borderRadius: 4,
              background: 'rgba(255, 255, 255, 0.04)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              color: currentPage === 1 ? 'rgba(255,255,255,0.2)' : 'var(--text-primary)',
              cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
              fontSize: '0.75rem',
            }}
          >
            ◀ Prev
          </button>

          <span style={{ padding: '0 8px', fontFamily: 'JetBrains Mono' }}>
            Page {currentPage} of {totalPages}
          </span>

          <button
            disabled={currentPage >= totalPages}
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            style={{
              padding: '4px 10px',
              borderRadius: 4,
              background: 'rgba(255, 255, 255, 0.04)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              color: currentPage >= totalPages ? 'rgba(255,255,255,0.2)' : 'var(--text-primary)',
              cursor: currentPage >= totalPages ? 'not-allowed' : 'pointer',
              fontSize: '0.75rem',
            }}
          >
            Next ▶
          </button>
        </div>
      </div>
    </div>
  );
}
