'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { useLiveFeed } from '@/lib/useLiveFeed';

/**
 * Enterprise SOC Autonomous Attack Notification System
 *
 * Real-time audio & visual threat alert center:
 * - Listens for incoming attacks, alerts, and autonomous IPS blocks
 * - Synthesizes tactical audio alerts via Web Audio API (zero external dependencies)
 * - Fires native OS desktop notifications via Notification API
 * - Renders sleek cyber-HUD glassmorphic toast cards with quick action links
 */

let toastIdCounter = 0;

// ── Web Audio API Tactical Chime Synthesizer ─────────────────────────────────
function playAttackAlertSound(severity = 'CRITICAL') {
  if (typeof window === 'undefined') return;
  try {
    const isMuted = localStorage.getItem('ids_sound_enabled') === 'false';
    if (isMuted) return;

    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;

    const ctx = new AudioContextClass();
    const now = ctx.currentTime;

    const isCrit = severity === 'CRITICAL';
    const osc1 = ctx.createOscillator();
    const osc2 = ctx.createOscillator();
    const gain = ctx.createGain();

    osc1.type = isCrit ? 'sawtooth' : 'sine';
    osc2.type = 'sine';

    // Frequencies: High-urgency tactical alert radar pulse
    osc1.frequency.setValueAtTime(isCrit ? 880 : 740, now);
    osc1.frequency.exponentialRampToValueAtTime(isCrit ? 440 : 587, now + 0.16);

    osc2.frequency.setValueAtTime(isCrit ? 1320 : 1108, now);
    osc2.frequency.exponentialRampToValueAtTime(isCrit ? 660 : 880, now + 0.16);

    // Second pulse for critical severity
    if (isCrit) {
      osc1.frequency.setValueAtTime(920, now + 0.2);
      osc1.frequency.exponentialRampToValueAtTime(460, now + 0.36);
    }

    gain.gain.setValueAtTime(0.12, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + (isCrit ? 0.42 : 0.28));

    osc1.connect(gain);
    osc2.connect(gain);
    gain.connect(ctx.destination);

    osc1.start(now);
    osc2.start(now);
    osc1.stop(now + (isCrit ? 0.45 : 0.3));
    osc2.stop(now + (isCrit ? 0.45 : 0.3));
  } catch {
    // Gracefully ignore autoplay restrictions if user hasn't interacted yet
  }
}

// ── Browser Desktop Notification ─────────────────────────────────────────────
function sendDesktopNotification(title, body) {
  if (typeof window === 'undefined' || !('Notification' in window)) return;
  if (Notification.permission === 'granted') {
    try {
      const notif = new Notification(title, {
        body,
        icon: '/favicon.ico',
        tag: `ids-alert-${Date.now()}`,
      });
      notif.onclick = () => {
        window.focus();
        if (window.location.pathname !== '/alerts') {
          window.location.href = '/alerts';
        }
      };
    } catch {
      // Ignore background notification restrictions
    }
  }
}

export function ToastContainer() {
  const [toasts, setToasts] = useState([]);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const seenIdsRef = useRef(new Set());

  // Ensure persistent WebSocket connection across every page in RootLayout
  useLiveFeed(20);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('ids_sound_enabled');
      if (saved !== null) {
        setSoundEnabled(saved !== 'false');
      }
      // Request desktop notification permission if not yet decided
      if ('Notification' in window && Notification.permission === 'default') {
        const handleFirstInteraction = () => {
          Notification.requestPermission();
          window.removeEventListener('click', handleFirstInteraction);
        };
        window.addEventListener('click', handleFirstInteraction, { once: true });
      }
    }
  }, []);

  const toggleSound = () => {
    const next = !soundEnabled;
    setSoundEnabled(next);
    if (typeof window !== 'undefined') {
      localStorage.setItem('ids_sound_enabled', String(next));
    }
  };

  const addToast = useCallback((toast) => {
    const id = ++toastIdCounter;
    setToasts((prev) => [{ ...toast, id, exiting: false }, ...prev.slice(0, 4)]);

    // Auto-dismiss after duration
    const duration = toast.duration || (toast.type === 'critical' ? 9000 : 6000);
    setTimeout(() => {
      setToasts((prev) =>
        prev.map((t) => (t.id === id ? { ...t, exiting: true } : t))
      );
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 400);
    }, duration);
  }, []);

  const dismiss = useCallback((id) => {
    setToasts((prev) =>
      prev.map((t) => (t.id === id ? { ...t, exiting: true } : t))
    );
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 400);
  }, []);

  // Expose manual toast API globally
  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.showToast = (message, type = 'info', title = null, duration = undefined) => {
      addToast({ message, type, title, duration });
    };
    return () => {
      delete window.showToast;
    };
  }, [addToast]);

  // Listen for live security events and autonomous attack triggers
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handler = (e) => {
      const ev = e.detail || {};
      if (!ev) return;

      // Deduplicate by event / alert id within 12 seconds
      const dedupKey = ev.id || `${ev.src_ip || ''}-${ev.signature || ''}-${ev.action || ''}`;
      if (dedupKey && seenIdsRef.current.has(dedupKey)) {
        return;
      }
      if (dedupKey) {
        seenIdsRef.current.add(dedupKey);
        setTimeout(() => {
          seenIdsRef.current.delete(dedupKey);
        }, 12000);
      }

      const sev = (ev.severity || '').toUpperCase();
      const action = (ev.action || '').toUpperCase();
      const isIpsBlock = action === 'BLOCK' || action === 'ISOLATE';
      const isAttack =
        sev === 'CRITICAL' ||
        sev === 'HIGH' ||
        sev === 'MEDIUM' ||
        isIpsBlock ||
        ev.autonomous_mitigation?.prevented ||
        Boolean(ev.signature);

      if (isAttack) {
        const toastType =
          sev === 'CRITICAL' || isIpsBlock
            ? 'critical'
            : sev === 'HIGH'
            ? 'warning'
            : sev === 'MEDIUM'
            ? 'info'
            : 'info';

        const icon =
          sev === 'CRITICAL'
            ? '🚨'
            : isIpsBlock
            ? '🛡️'
            : sev === 'HIGH'
            ? '⚠️'
            : '⚡';

        const title = isIpsBlock
          ? `AUTONOMOUS IPS CONTAINMENT`
          : `${sev || 'CYBER'} ATTACK INTERCEPTED`;

        const srcIp = ev.src_ip || ev.ip_address || 'External Threat Actor';
        const dstIp = ev.dst_ip ? ` ➔ ${ev.dst_ip}${ev.dst_port ? `:${ev.dst_port}` : ''}` : '';
        const sig =
          ev.signature ||
          ev.reason ||
          ev.title ||
          (isIpsBlock ? `Malicious Host ${srcIp} Quarantined` : 'Suspicious Network Intrusion');

        const mitigation =
          ev.autonomous_mitigation?.action ||
          (isIpsBlock ? 'KERNEL_EBPF_DISCARD' : (ev.status === 'AUTO_BLOCKED' ? 'AUTO_BLOCKED' : null));

        // Play audio alert
        playAttackAlertSound(sev || 'CRITICAL');

        // Send desktop notification if supported
        sendDesktopNotification(
          `${icon} ${title}: ${srcIp}`,
          `${sig} ${mitigation ? `[${mitigation}]` : ''}`
        );

        addToast({
          type: toastType,
          title: `${icon} ${title}`,
          signature: sig,
          src_ip: srcIp,
          dst_ip: dstIp,
          severity: sev || 'CRITICAL',
          mitigation: mitigation,
          alert_id: ev.id,
          duration: toastType === 'critical' ? 10000 : 7000,
        });
      }
    };

    window.addEventListener('ids-live-event', handler);
    return () => window.removeEventListener('ids-live-event', handler);
  }, [addToast]);

  return (
    <div
      id="toast-container"
      style={{
        position: 'fixed',
        top: 20,
        right: 20,
        zIndex: 99999,
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        pointerEvents: 'none',
        maxWidth: 420,
        width: 'calc(100vw - 40px)',
      }}
    >
      {toasts.length > 0 && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', pointerEvents: 'all', marginBottom: -4 }}>
          <button
            onClick={toggleSound}
            style={{
              background: 'rgba(2, 6, 23, 0.85)',
              border: '1px solid rgba(255,255,255,0.15)',
              borderRadius: 20,
              padding: '3px 10px',
              fontSize: '0.68rem',
              fontWeight: 600,
              color: soundEnabled ? 'var(--accent-cyan)' : 'var(--text-muted)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 5,
              backdropFilter: 'blur(8px)',
            }}
            title={soundEnabled ? 'Alert Chime Enabled (Click to Mute)' : 'Alert Chime Muted (Click to Enable)'}
          >
            {soundEnabled ? '🔔 Alert Audio ON' : '🔕 Alert Audio OFF'}
          </button>
        </div>
      )}

      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} onDismiss={dismiss} />
      ))}
    </div>
  );
}

function ToastItem({ toast, onDismiss }) {
  const colors = {
    critical: {
      border: '#ef4444',
      bg: 'rgba(239, 68, 68, 0.16)',
      glow: 'rgba(239, 68, 68, 0.45)',
      bar: '#ef4444',
      titleColor: '#fca5a5',
      badgeBg: 'rgba(239, 68, 68, 0.25)',
    },
    warning: {
      border: '#f59e0b',
      bg: 'rgba(245, 158, 11, 0.14)',
      glow: 'rgba(245, 158, 11, 0.35)',
      bar: '#f59e0b',
      titleColor: '#fcd34d',
      badgeBg: 'rgba(245, 158, 11, 0.25)',
    },
    info: {
      border: '#00d4ff',
      bg: 'rgba(0, 212, 255, 0.12)',
      glow: 'rgba(0, 212, 255, 0.3)',
      bar: '#00d4ff',
      titleColor: '#67e8f9',
      badgeBg: 'rgba(0, 212, 255, 0.2)',
    },
  };

  const c = colors[toast.type] || colors.critical;
  const duration = toast.duration || 8000;

  return (
    <div
      style={{
        pointerEvents: 'all',
        background: `linear-gradient(135deg, ${c.bg}, rgba(4, 9, 20, 0.96))`,
        border: `1px solid ${c.border}`,
        borderRadius: 10,
        padding: '14px 16px',
        boxShadow: `0 12px 40px rgba(0,0,0,0.7), 0 0 24px ${c.glow}`,
        backdropFilter: 'blur(20px)',
        animation: toast.exiting
          ? 'toastSlideOut 0.35s ease forwards'
          : 'toastSlideIn 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Progress bar */}
      <div
        style={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          height: 3,
          width: '100%',
          background: 'rgba(255,255,255,0.08)',
          borderRadius: '0 0 10px 10px',
        }}
      >
        <div
          style={{
            height: '100%',
            background: c.bar,
            borderRadius: '0 0 10px 10px',
            animation: `toastProgress ${duration}ms linear forwards`,
            boxShadow: `0 0 8px ${c.bar}`,
          }}
        />
      </div>

      {/* Header Row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <span className="live-dot" style={{ width: 7, height: 7, background: c.border }} />
          <span
            style={{
              fontSize: '0.78rem',
              fontWeight: 800,
              color: c.titleColor,
              letterSpacing: '0.04em',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            {toast.title}
          </span>
        </div>

        {/* Dismiss X */}
        <button
          onClick={() => onDismiss(toast.id)}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            fontSize: '1.1rem',
            lineHeight: 1,
            padding: '0 4px',
          }}
          aria-label="Dismiss alert"
        >
          ×
        </button>
      </div>

      {/* Signature */}
      <div
        style={{
          fontSize: '0.85rem',
          fontWeight: 700,
          color: 'var(--text-primary)',
          lineHeight: 1.35,
          marginBottom: 6,
        }}
      >
        {toast.signature || toast.message}
      </div>

      {/* Attack Vector Coordinates */}
      {toast.src_ip && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            fontSize: '0.74rem',
            color: 'var(--text-secondary)',
            fontFamily: 'JetBrains Mono, monospace',
            marginBottom: 8,
            padding: '3px 8px',
            borderRadius: 4,
            background: 'rgba(0,0,0,0.35)',
            border: '1px solid rgba(255,255,255,0.06)',
          }}
        >
          <span style={{ color: 'var(--text-muted)' }}>Vector:</span>
          <span style={{ color: '#fca5a5', fontWeight: 600 }}>{toast.src_ip}</span>
          {toast.dst_ip && <span>{toast.dst_ip}</span>}
        </div>
      )}

      {/* Bottom Footer Row: Mitigation Badge + Navigation Link */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 4 }}>
        {toast.mitigation ? (
          <span
            style={{
              fontSize: '0.68rem',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: 4,
              background: 'rgba(16, 185, 129, 0.18)',
              border: '1px solid rgba(16, 185, 129, 0.4)',
              color: '#34d399',
              fontFamily: 'JetBrains Mono, monospace',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
            }}
          >
            🛡️ {toast.mitigation}
          </span>
        ) : (
          <span
            style={{
              fontSize: '0.68rem',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: 4,
              background: c.badgeBg,
              border: `1px solid ${c.border}`,
              color: c.titleColor,
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            {toast.severity || 'THREAT'}
          </span>
        )}

        <a
          href="/alerts"
          style={{
            fontSize: '0.74rem',
            fontWeight: 700,
            color: 'var(--accent-cyan)',
            textDecoration: 'none',
            display: 'flex',
            alignItems: 'center',
            gap: 4,
          }}
          onClick={() => onDismiss(toast.id)}
        >
          Inspect Alert ➔
        </a>
      </div>
    </div>
  );
}
