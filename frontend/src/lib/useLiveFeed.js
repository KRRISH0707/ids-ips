'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { getToken, ensureAuth, api } from './api';

// ── Global Singleton WebSocket & Event Dispatcher ──────────────────────────────
let globalWs = null;
let globalReconnectTimer = null;
let isConnecting = false;
let listeners = new Set();
let seenAlertIds = new Set();
let pollerInterval = null;
let lastPollerRun = 0;

function broadcastLiveEvent(enrichedMsg) {
  // Deduplicate by ID if present
  if (enrichedMsg.id) {
    seenAlertIds.add(String(enrichedMsg.id));
    if (seenAlertIds.size > 1000) {
      const arr = Array.from(seenAlertIds);
      seenAlertIds = new Set(arr.slice(-500));
    }
  }

  // Notify internal React hook listeners
  listeners.forEach((fn) => {
    try {
      fn(enrichedMsg);
    } catch (err) {
      console.error('Live listener error:', err);
    }
  });

  // Dispatch global window event for components like ToastContainer
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('ids-live-event', { detail: enrichedMsg }));
  }
}

async function connectGlobalWebSocket() {
  if (typeof window === 'undefined') return;
  if (globalWs && (globalWs.readyState === WebSocket.OPEN || globalWs.readyState === WebSocket.CONNECTING)) {
    return;
  }
  if (isConnecting) return;

  isConnecting = true;
  let token = getToken();
  if (!token) {
    token = await ensureAuth();
  }
  if (!token) {
    isConnecting = false;
    if (!globalReconnectTimer) {
      globalReconnectTimer = setTimeout(connectGlobalWebSocket, 4000);
    }
    return;
  }

  let wsBase = process.env.NEXT_PUBLIC_WS_URL;
  if (!wsBase) {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    wsBase = `${proto}//${window.location.host}`;
  }
  const url = `${wsBase}/api/ws/live?token=${encodeURIComponent(token)}`;

  try {
    const ws = new WebSocket(url);
    globalWs = ws;

    ws.onopen = () => {
      isConnecting = false;
      if (globalReconnectTimer) {
        clearTimeout(globalReconnectTimer);
        globalReconnectTimer = null;
      }
      // Broadcast connection state
      listeners.forEach((fn) => fn({ _type: 'STATUS', isConnected: true }));
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        const enrichedMsg = { ...msg, _ts: Date.now() };
        broadcastLiveEvent(enrichedMsg);
      } catch {
        // Ignore non-JSON ping/pong
      }
    };

    ws.onerror = () => {
      isConnecting = false;
    };

    ws.onclose = (e) => {
      isConnecting = false;
      globalWs = null;
      listeners.forEach((fn) => fn({ _type: 'STATUS', isConnected: false }));
      if (e.code !== 1000) {
        if (!globalReconnectTimer) {
          globalReconnectTimer = setTimeout(() => {
            globalReconnectTimer = null;
            connectGlobalWebSocket();
          }, 4000);
        }
      }
    };
  } catch (err) {
    isConnecting = false;
    if (!globalReconnectTimer) {
      globalReconnectTimer = setTimeout(() => {
        globalReconnectTimer = null;
        connectGlobalWebSocket();
      }, 5000);
    }
  }
}

// ── Fallback Polling Safety Net ───────────────────────────────────────────────
// Periodically checks /api/alerts?limit=8 to ensure that any attacks simulated or
// detected while WebSocket is reconnecting are NEVER missed.
function startFallbackPoller() {
  if (typeof window === 'undefined' || pollerInterval) return;

  pollerInterval = setInterval(async () => {
    // Only poll if window is active and at least 3.5s passed
    const now = Date.now();
    if (now - lastPollerRun < 3500) return;
    lastPollerRun = now;

    try {
      const token = getToken();
      if (!token) return;

      const res = await api.getAlerts({ limit: 8 });
      const items = res?.items || [];
      if (!Array.isArray(items)) return;

      // Check for alerts created within the last 30s that we haven't seen
      const thirtySecAgo = Date.now() - 30000;
      for (const alert of items) {
        if (!alert.id) continue;
        const alertIdStr = String(alert.id);
        const alertTime = alert.timestamp ? new Date(alert.timestamp).getTime() : 0;

        if (!seenAlertIds.has(alertIdStr)) {
          seenAlertIds.add(alertIdStr);
          // If this is a recent alert, broadcast it
          if (alertTime >= thirtySecAgo) {
            broadcastLiveEvent({
              ...alert,
              _from_poller: true,
              _ts: Date.now(),
            });
          }
        }
      }
    } catch {
      // Silently ignore background polling errors
    }
  }, 4000);
}

/**
 * Connect to the IDS/IPS WebSocket live feed.
 * Returns { messages, lastMessage, isConnected, error }
 */
export function useLiveFeed(maxMessages = 50) {
  const [messages, setMessages] = useState([]);
  const [lastMessage, setLastMessage] = useState(null);
  const [isConnected, setIsConnected] = useState(
    Boolean(globalWs && globalWs.readyState === WebSocket.OPEN)
  );

  useEffect(() => {
    connectGlobalWebSocket();
    startFallbackPoller();

    const listener = (msg) => {
      if (msg._type === 'STATUS') {
        setIsConnected(Boolean(msg.isConnected));
        return;
      }

      setLastMessage(msg);
      setMessages((prev) => [msg, ...prev.slice(0, maxMessages - 1)]);
    };

    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }, [maxMessages]);

  return { messages, lastMessage, isConnected };
}

/**
 * Hook to execute a callback whenever any live event (attack, alert, incident, IPS action, audit log) is broadcast.
 */
export function useOnLiveEvent(callback) {
  const cbRef = useRef(callback);
  cbRef.current = callback;

  // Ensure global connection is active
  useLiveFeed(10);

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handler = (e) => {
      if (cbRef.current) {
        cbRef.current(e.detail);
      }
    };

    window.addEventListener('ids-live-event', handler);
    return () => window.removeEventListener('ids-live-event', handler);
  }, []);
}
