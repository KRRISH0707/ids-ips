'use client';

import { useState, useEffect } from 'react';

/**
 * Tactical audio synthesizer for audio toggle feedback
 */
function playToggleFeedbackChime(enabled) {
  if (typeof window === 'undefined') return;
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;
    const ctx = new AudioContextClass();
    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    if (enabled) {
      // Crisp 2-tone tactical chime: 587Hz -> 880Hz
      osc.type = 'sine';
      osc.frequency.setValueAtTime(587.33, now);
      osc.frequency.exponentialRampToValueAtTime(880, now + 0.14);
      gain.gain.setValueAtTime(0.15, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.32);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.33);
    } else {
      // Soft low confirmation tone: 440Hz -> 261Hz
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(440, now);
      osc.frequency.exponentialRampToValueAtTime(261.63, now + 0.12);
      gain.gain.setValueAtTime(0.1, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.21);
    }
  } catch {
    // Ignore browser autoplay constraints
  }
}

/**
 * Permanent Alert Sound Toggle Button
 * - Globally accessible from top navigation bar and sidebar
 * - Persists preference in localStorage ('ids_sound_enabled')
 * - Broadcasts events so all instances remain synchronized
 * - Synthesizes instant audio confirmation
 */
export default function AlertSoundToggle({ compact = false }) {
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const readPreference = () => {
      const saved = localStorage.getItem('ids_sound_enabled');
      if (saved !== null) {
        setSoundEnabled(saved !== 'false');
      } else {
        setSoundEnabled(true);
      }
    };

    readPreference();

    const handleSync = (e) => {
      if (e?.detail?.enabled !== undefined) {
        setSoundEnabled(e.detail.enabled);
      } else {
        readPreference();
      }
    };

    window.addEventListener('ids_sound_toggle', handleSync);
    window.addEventListener('storage', readPreference);
    return () => {
      window.removeEventListener('ids_sound_toggle', handleSync);
      window.removeEventListener('storage', readPreference);
    };
  }, []);

  const handleToggle = (e) => {
    e?.stopPropagation?.();
    const nextState = !soundEnabled;
    setSoundEnabled(nextState);

    if (typeof window !== 'undefined') {
      localStorage.setItem('ids_sound_enabled', String(nextState));
      window.dispatchEvent(new CustomEvent('ids_sound_toggle', { detail: { enabled: nextState } }));

      // Play audio feedback chime
      playToggleFeedbackChime(nextState);

      // Brief HUD notification
      if (window.showToast) {
        if (nextState) {
          window.showToast('Tactical cyber threat audio alerts enabled.', 'info', '🔊 Alert Audio Active', 2600);
        } else {
          window.showToast('Audio alerts muted. Visual HUD toasts remain active.', 'warning', '🔇 Alert Audio Muted', 2600);
        }
      }
    }
  };

  if (!mounted) {
    return (
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: compact ? '4px 8px' : '5px 12px',
          borderRadius: 8,
          background: 'rgba(6, 13, 24, 0.7)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          fontSize: '0.72rem',
          color: 'var(--text-muted)',
          height: 32,
        }}
      >
        <span>🔊</span>
        <span>SOUND: ...</span>
      </div>
    );
  }

  if (compact) {
    return (
      <button
        onClick={handleToggle}
        className="btn btn-ghost btn-sm"
        title={soundEnabled ? 'Alert audio is ON (click to mute)' : 'Alert audio is MUTED (click to unmute)'}
        style={{
          padding: '4px 8px',
          fontSize: '0.72rem',
          borderRadius: 6,
          display: 'inline-flex',
          alignItems: 'center',
          gap: 5,
          background: soundEnabled ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
          border: `1px solid ${soundEnabled ? 'rgba(16, 185, 129, 0.35)' : 'rgba(239, 68, 68, 0.35)'}`,
          color: soundEnabled ? '#34d399' : '#f87171',
          cursor: 'pointer',
          transition: 'all 0.2s ease',
        }}
      >
        <span>{soundEnabled ? '🔊' : '🔇'}</span>
        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, fontSize: '0.68rem' }}>
          {soundEnabled ? 'SOUND ON' : 'MUTED'}
        </span>
      </button>
    );
  }

  return (
    <button
      onClick={handleToggle}
      className="btn btn-ghost btn-sm"
      title={soundEnabled ? 'Threat detection audio alarm is ACTIVE. Click to mute.' : 'Threat detection audio alarm is MUTED. Click to activate.'}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        padding: '5px 12px',
        borderRadius: 8,
        background: soundEnabled
          ? 'linear-gradient(135deg, rgba(16, 185, 129, 0.14) 0%, rgba(6, 182, 212, 0.12) 100%)'
          : 'rgba(15, 23, 42, 0.65)',
        border: `1px solid ${soundEnabled ? 'rgba(16, 185, 129, 0.45)' : 'rgba(255, 255, 255, 0.12)'}`,
        color: soundEnabled ? '#f8fafc' : 'var(--text-muted)',
        cursor: 'pointer',
        boxShadow: soundEnabled ? '0 0 14px rgba(16, 185, 129, 0.2)' : 'none',
        transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
        userSelect: 'none',
        height: 32,
      }}
    >
      <span style={{ fontSize: '0.92rem', lineHeight: 1 }}>
        {soundEnabled ? '🔊' : '🔇'}
      </span>

      <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.74rem', fontWeight: 700, letterSpacing: '0.02em' }}>
        <span>ALERT AUDIO:</span>
        <span
          style={{
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '0.7rem',
            fontWeight: 800,
            padding: '1px 6px',
            borderRadius: 4,
            background: soundEnabled ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.2)',
            border: `1px solid ${soundEnabled ? '#10b981' : '#ef4444'}`,
            color: soundEnabled ? '#34d399' : '#f87171',
          }}
        >
          {soundEnabled ? 'ON' : 'OFF'}
        </span>
      </span>

      {soundEnabled && (
        <span
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: '#10b981',
            boxShadow: '0 0 8px #10b981',
            animation: 'pulse 1.8s infinite',
          }}
        />
      )}
    </button>
  );
}
