'use client';

import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * Global Toast Notification System
 *
 * Listens to the `ids-live-event` window event (dispatched by useLiveFeed) and
 * shows slide-in toasts for HIGH / CRITICAL severity threats.
 * Also exposes `window.showToast(message, type)` for manual toasts.
 */

let toastIdCounter = 0;

export function ToastContainer() {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((toast) => {
    const id = ++toastIdCounter;
    setToasts((prev) => [{ ...toast, id, exiting: false }, ...prev.slice(0, 4)]);

    // Auto-dismiss after duration
    const duration = toast.duration || (toast.type === 'critical' ? 8000 : 5000);
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
    return () => { delete window.showToast; };
  }, [addToast]);

  // Listen for live security events
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handler = (e) => {
      const ev = e.detail || {};
      const sev = (ev.severity || '').toUpperCase();
      const type = ev.type || '';

      // Only toast for HIGH/CRITICAL alerts or important events
      if (sev === 'CRITICAL' || sev === 'HIGH' || type === 'IPS_ACTION') {
        const toastType = sev === 'CRITICAL' ? 'critical' : sev === 'HIGH' ? 'warning' : 'info';
        const icon = sev === 'CRITICAL' ? '🚨' : sev === 'HIGH' ? '⚠️' : '🛡️';
        const title =
          type === 'IPS_ACTION'
            ? `IPS: IP Quarantined`
            : `${sev} Threat Detected`;

        const src = ev.src_ip ? ` from ${ev.src_ip}` : '';
        const sig = ev.signature
          ? ev.signature.length > 60
            ? ev.signature.slice(0, 57) + '…'
            : ev.signature
          : null;

        addToast({
          type: toastType,
          title: `${icon} ${title}`,
          message: sig || `Severity: ${sev}${src}`,
          duration: toastType === 'critical' ? 9000 : 6000,
        });
      }
    };

    window.addEventListener('ids-live-event', handler);
    return () => window.removeEventListener('ids-live-event', handler);
  }, [addToast]);

  if (toasts.length === 0) return null;

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
        gap: 10,
        pointerEvents: 'none',
        maxWidth: 380,
        width: '100%',
      }}
    >
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
      bg: 'rgba(239, 68, 68, 0.12)',
      glow: 'rgba(239, 68, 68, 0.3)',
      bar: '#ef4444',
      titleColor: '#fca5a5',
    },
    warning: {
      border: '#f59e0b',
      bg: 'rgba(245, 158, 11, 0.1)',
      glow: 'rgba(245, 158, 11, 0.25)',
      bar: '#f59e0b',
      titleColor: '#fcd34d',
    },
    success: {
      border: '#10b981',
      bg: 'rgba(16, 185, 129, 0.1)',
      glow: 'rgba(16, 185, 129, 0.2)',
      bar: '#10b981',
      titleColor: '#6ee7b7',
    },
    info: {
      border: '#00d4ff',
      bg: 'rgba(0, 212, 255, 0.08)',
      glow: 'rgba(0, 212, 255, 0.2)',
      bar: '#00d4ff',
      titleColor: '#67e8f9',
    },
  };

  const c = colors[toast.type] || colors.info;
  const duration = toast.duration || 5000;

  return (
    <div
      style={{
        pointerEvents: 'all',
        background: `linear-gradient(135deg, ${c.bg}, rgba(6, 13, 24, 0.95))`,
        border: `1px solid ${c.border}`,
        borderRadius: 10,
        padding: '12px 16px',
        boxShadow: `0 8px 32px rgba(0,0,0,0.6), 0 0 20px ${c.glow}`,
        backdropFilter: 'blur(16px)',
        animation: toast.exiting
          ? 'toastSlideOut 0.35s ease forwards'
          : 'toastSlideIn 0.35s ease forwards',
        position: 'relative',
        overflow: 'hidden',
        cursor: 'pointer',
      }}
      onClick={() => onDismiss(toast.id)}
      title="Click to dismiss"
    >
      {/* Progress bar */}
      <div
        style={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          height: 3,
          width: '100%',
          background: `rgba(255,255,255,0.08)`,
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

      {toast.title && (
        <div
          style={{
            fontSize: '0.82rem',
            fontWeight: 700,
            color: c.titleColor,
            marginBottom: 4,
            letterSpacing: '0.02em',
          }}
        >
          {toast.title}
        </div>
      )}
      <div
        style={{
          fontSize: '0.8rem',
          color: '#cbd5e1',
          lineHeight: 1.4,
        }}
      >
        {toast.message}
      </div>

      {/* Dismiss X */}
      <button
        onClick={(e) => { e.stopPropagation(); onDismiss(toast.id); }}
        style={{
          position: 'absolute',
          top: 8,
          right: 10,
          background: 'none',
          border: 'none',
          color: 'var(--text-muted)',
          cursor: 'pointer',
          fontSize: '0.9rem',
          lineHeight: 1,
          padding: 2,
        }}
        aria-label="Dismiss"
      >
        ×
      </button>
    </div>
  );
}
