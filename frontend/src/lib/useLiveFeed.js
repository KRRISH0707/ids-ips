'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { getToken } from './api';

const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000';

/**
 * Connect to the IDS/IPS WebSocket live feed.
 * Returns { messages, isConnected, error }
 */
export function useLiveFeed(maxMessages = 50) {
  const [messages, setMessages] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState(null);
  const wsRef = useRef(null);

  const connect = useCallback(() => {
    const token = getToken();
    if (!token) return;

    const url = `${WS_BASE}/api/ws/live?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      setError(null);
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        setMessages((prev) => [
          { ...msg, _ts: Date.now() },
          ...prev.slice(0, maxMessages - 1),
        ]);
      } catch {
        // ignore non-JSON
      }
    };

    ws.onerror = () => setError('WebSocket connection error');

    ws.onclose = (e) => {
      setIsConnected(false);
      if (e.code !== 1000) {
        // Reconnect after 3s on unintentional close
        setTimeout(connect, 3000);
      }
    };
  }, [maxMessages]);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close(1000, 'component unmounted');
    };
  }, [connect]);

  return { messages, isConnected, error };
}
