'use client';

import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { api } from '@/lib/api';
import { Spinner } from '@/components/ui';

export default function PCAPViewerModal({ alertId, onClose }) {
  const [mounted, setMounted] = useState(false);
  const [trace, setTrace] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    setMounted(true);
    const origOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = origOverflow;
    };
  }, []);

  useEffect(() => {
    async function loadTrace() {
      try {
        setLoading(true);
        const data = await api.getPacketTrace(alertId);
        setTrace(data);
      } catch (err) {
        setError(err.message || 'Failed to load packet trace');
      } finally {
        setLoading(false);
      }
    }
    if (alertId) {
      loadTrace();
    }
  }, [alertId]);

  const handleDownloadPcap = () => {
    const apiBase = typeof window !== 'undefined' ? `${window.location.protocol}//${window.location.hostname}:8000` : '';
    const token = typeof window !== 'undefined' ? localStorage.getItem('ids_access_token') : '';
    // Trigger download
    fetch(`${apiBase}/api/alerts/${alertId}/pcap`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.blob())
      .then((blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `alert_${String(alertId).slice(0, 8)}.pcap`;
        document.body.appendChild(a);
        a.click();
        a.remove();
      })
      .catch((err) => alert('Failed to download PCAP: ' + err.message));
  };

  if (!mounted || typeof document === 'undefined') return null;

  return createPortal(
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        width: '100vw',
        height: '100vh',
        background: 'rgba(2, 4, 8, 0.88)',
        backdropFilter: 'blur(10px)',
        WebkitBackdropFilter: 'blur(10px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 999999,
        padding: 20,
      }}
      onClick={onClose}
    >
      <div
        className="glass-card"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '90%',
          maxWidth: 860,
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          padding: 24,
          overflow: 'hidden',
        }}
      >
        {/* Modal Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 14, marginBottom: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: '1.2rem' }}>📦</span>
              <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700 }}>
                Deep Packet Inspection (DPI) & PCAP Dissector
              </h3>
              <span style={{ fontSize: '0.7rem', padding: '2px 6px', borderRadius: 4, background: 'rgba(59, 130, 246, 0.2)', color: '#60a5fa', fontFamily: 'monospace' }}>
                Frame #1
              </span>
            </div>
            <p style={{ margin: '4px 0 0', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Alert Trace ID: <span style={{ fontFamily: 'monospace' }}>{alertId}</span>
            </p>
          </div>

          <div style={{ display: 'flex', gap: 10 }}>
            <button className="btn btn-primary btn-sm" onClick={handleDownloadPcap}>
              ⬇ Download .pcap
            </button>
            <button className="btn btn-ghost btn-sm" onClick={onClose}>
              ✕
            </button>
          </div>
        </div>

        {/* Modal Content */}
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
          {loading ? (
            <div style={{ padding: 40, textAlign: 'center' }}>
              <Spinner />
            </div>
          ) : error ? (
            <div style={{ color: 'var(--sev-critical)', padding: 20 }}>{error}</div>
          ) : (
            <>
              {/* Protocol Dissection Tree */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {/* Frame */}
                <div style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.05)', fontSize: '0.8rem' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>▶ Frame 1: </span>
                  <span style={{ color: 'var(--text-secondary)' }}>
                    {trace.frame.length} bytes on wire ({trace.frame.captured_length} bytes captured) on interface eth0 [{trace.frame.protocols}]
                  </span>
                </div>

                {/* Ethernet II */}
                <div style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.05)', fontSize: '0.8rem' }}>
                  <span style={{ color: 'var(--accent-purple)', fontWeight: 700 }}>▶ Ethernet II: </span>
                  <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                    Src: {trace.ethernet.source_mac}, Dst: {trace.ethernet.destination_mac}, Type: {trace.ethernet.type}
                  </span>
                </div>

                {/* IPv4 */}
                <div style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.05)', fontSize: '0.8rem' }}>
                  <span style={{ color: '#38bdf8', fontWeight: 700 }}>▶ Internet Protocol Version 4: </span>
                  <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                    Src: {trace.ip.source}, Dst: {trace.ip.destination}, TTL: {trace.ip.ttl}, Protocol: {trace.ip.protocol}
                  </span>
                </div>

                {/* Transport (TCP/UDP) */}
                <div style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.05)', fontSize: '0.8rem' }}>
                  <span style={{ color: '#fbbf24', fontWeight: 700 }}>▶ {trace.transport.protocol}: </span>
                  <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                    Src Port: {trace.transport.source_port}, Dst Port: {trace.transport.destination_port}, Flags: {trace.transport.flags}, Seq: {trace.transport.sequence_number}
                  </span>
                </div>
              </div>

              {/* Raw Hex Dump & ASCII Inspector */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Packet Hex Byte Dissection (Offset | Raw Bytes | ASCII Representation)
                  </span>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    Total Payload: {trace.payload.bytes_total} Bytes
                  </span>
                </div>

                <div
                  style={{
                    background: '#020617',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: 6,
                    padding: 14,
                    fontFamily: 'Consolas, monospace',
                    fontSize: '0.75rem',
                    lineHeight: '1.4',
                    color: '#38bdf8',
                    overflowX: 'auto',
                    userSelect: 'text',
                  }}
                >
                  {(trace.payload.hex_dump || []).map((line, idx) => (
                    <div key={idx} style={{ whiteSpace: 'pre' }}>
                      {line}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>,
    document.body
  );
}
