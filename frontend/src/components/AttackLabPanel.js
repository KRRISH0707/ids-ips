'use client';

import { useState } from 'react';
import { ATTACK_SCENARIOS, ATTACK_CATEGORIES } from '@/lib/attackScenarios';
import AttackResolutionPipeline from './AttackResolutionPipeline';
import AttackDossierModal from './AttackDossierModal';

/**
 * AttackLabPanel Component
 * Provides interactive cyber attack simulation tabs for all 6 attack categories:
 * MALWARE, NETWORK, CREDENTIAL, WEB/API, EXPLOITATION, POST-COMPROMISE.
 */
export default function AttackLabPanel({
  onAttackTriggered = () => {},
  onResetBaseline = () => {},
  activeAttackId = null,
}) {
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [activeAttack, setActiveAttack] = useState(ATTACK_SCENARIOS[0]);
  const [selectedDossierAttack, setSelectedDossierAttack] = useState(null);
  const [isResolving, setIsResolving] = useState(false);

  const filteredScenarios = selectedCategory === 'ALL'
    ? ATTACK_SCENARIOS
    : ATTACK_SCENARIOS.filter(a => a.categoryGroup === selectedCategory);

  const handleTriggerAttack = (attack) => {
    setActiveAttack(attack);
    setIsResolving(true);
    onAttackTriggered(attack);

    setTimeout(() => {
      setIsResolving(false);
    }, 900);
  };

  const handleReset = () => {
    setActiveAttack(null);
    setIsResolving(false);
    onResetBaseline();
  };

  return (
    <div className="glass-card" style={{ padding: 24, marginBottom: 24, border: '1px solid rgba(0, 212, 255, 0.25)', position: 'relative' }}>
      {/* Header with status badge */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18, flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: '1.2rem' }}>🧪</span>
            <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '0.02em' }}>
              Autonomous Threat Interception & Resolution Laboratory
            </h3>
            <span style={{
              fontSize: '0.68rem',
              fontWeight: 800,
              padding: '2px 8px',
              borderRadius: 4,
              background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.2), rgba(124, 58, 237, 0.2))',
              color: 'var(--accent-cyan)',
              border: '1px solid rgba(0, 212, 255, 0.4)',
              fontFamily: 'JetBrains Mono',
            }}>
              TAXONOMY AUDIT LAB
            </span>
          </div>
          <p style={{ margin: '4px 0 0', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Filter & trigger authentic attack vectors across all 6 attack categories. Witness sub-second neural anomaly detection, MITRE ATT&CK correlation, and autonomous kernel host quarantine.
          </p>
        </div>

        <button
          onClick={handleReset}
          className="btn btn-ghost btn-sm"
          style={{
            fontSize: '0.75rem',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            color: '#10b981',
            background: 'rgba(16, 185, 129, 0.08)',
          }}
        >
          🛡️ Reset to Guarded Baseline
        </button>
      </div>

      {/* Attack Category Filter Tabs */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, overflowX: 'auto', paddingBottom: 6 }}>
        {ATTACK_CATEGORIES.map(cat => {
          const isActive = selectedCategory === cat.id;
          return (
            <button
              key={cat.id}
              onClick={() => setSelectedCategory(cat.id)}
              style={{
                padding: '6px 14px',
                borderRadius: 6,
                fontSize: '0.75rem',
                fontWeight: isActive ? 800 : 500,
                background: isActive
                  ? 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)'
                  : 'rgba(255, 255, 255, 0.04)',
                border: isActive
                  ? '1px solid transparent'
                  : '1px solid rgba(255, 255, 255, 0.1)',
                color: isActive ? '#fff' : 'var(--text-muted)',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'all 0.2s ease',
              }}
            >
              {cat.name}
            </button>
          );
        })}
      </div>

      {/* Tactical Attack Scenario Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
        gap: 12,
        marginBottom: 20,
      }}>
        {filteredScenarios.map((atk) => {
          const isSelected = activeAttack?.id === atk.id;
          const isCritical = atk.badge === 'CRITICAL';

          return (
            <div
              key={atk.id}
              style={{
                borderRadius: 10,
                background: isSelected
                  ? 'linear-gradient(135deg, rgba(0, 212, 255, 0.12) 0%, rgba(124, 58, 237, 0.12) 100%)'
                  : 'rgba(255, 255, 255, 0.02)',
                border: isSelected
                  ? `1.5px solid ${isCritical ? '#ef4444' : 'var(--accent-cyan)'}`
                  : '1px solid rgba(255, 255, 255, 0.07)',
                boxShadow: isSelected
                  ? `0 0 20px ${isCritical ? 'rgba(239, 68, 68, 0.25)' : 'rgba(0, 212, 255, 0.2)'}`
                  : 'none',
                padding: '12px 14px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                transition: 'all 0.2s ease',
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                  <span style={{
                    fontSize: '0.65rem',
                    fontWeight: 800,
                    padding: '2px 6px',
                    borderRadius: 3,
                    background: isCritical ? 'rgba(239, 68, 68, 0.2)' : 'rgba(249, 115, 22, 0.2)',
                    color: isCritical ? '#ef4444' : '#f97316',
                    border: `1px solid ${isCritical ? 'rgba(239, 68, 68, 0.4)' : 'rgba(249, 115, 22, 0.4)'}`,
                  }}>
                    {atk.badge} · {atk.cvss.split(' ')[0]}
                  </span>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                    {atk.protocol}
                  </span>
                </div>

                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                  {atk.shortName}
                </div>

                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 12, lineHeight: 1.3 }}>
                  Target: <b style={{ color: 'var(--text-secondary)' }}>{atk.targetAsset.split(' ')[0]}</b> · {atk.actor.split(' / ')[0]}
                </div>
              </div>

              {/* Action Buttons: Trigger vs Inspect Dossier */}
              <div style={{ display: 'flex', gap: 6 }}>
                <button
                  onClick={() => handleTriggerAttack(atk)}
                  style={{
                    flex: 1,
                    padding: '6px 10px',
                    borderRadius: 6,
                    background: isSelected
                      ? 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)'
                      : 'rgba(0, 212, 255, 0.1)',
                    border: `1px solid ${isSelected ? 'transparent' : 'rgba(0, 212, 255, 0.3)'}`,
                    color: '#fff',
                    fontWeight: 700,
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 6,
                    transition: 'all 0.2s',
                  }}
                >
                  <span>⚡</span> {isSelected && isResolving ? 'Resolving...' : 'Trigger & Intercept'}
                </button>

                <button
                  onClick={() => setSelectedDossierAttack(atk)}
                  title="Inspect Real Payload, Hex Dump & MITRE ATT&CK Dossier"
                  style={{
                    padding: '6px 8px',
                    borderRadius: 6,
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid rgba(255, 255, 255, 0.12)',
                    color: 'var(--text-secondary)',
                    cursor: 'pointer',
                    fontSize: '0.75rem',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    transition: 'all 0.2s',
                  }}
                >
                  🔍 Dossier
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Real-Time Resolution Progress Ribbon */}
      <AttackResolutionPipeline activeAttack={activeAttack} isResolving={isResolving} />

      {/* Deep Threat Forensic Dossier Modal */}
      {selectedDossierAttack && (
        <AttackDossierModal
          attack={selectedDossierAttack}
          onClose={() => setSelectedDossierAttack(null)}
        />
      )}
    </div>
  );
}
