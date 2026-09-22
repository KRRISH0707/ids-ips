'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { getToken, ensureAuth } from './api';

const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000';

/**
 * Connect to the IDS/IPS WebSocket live feed.
 * Returns { messages, lastMessage, isConnected, error }
 */
export function useLiveFeed(maxMessages = 50) {
  const [messages, setMessages] = useState([]);
  const [lastMessage, setLastMessage] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState(null);
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  const connect = useCallback(async () => {
    let token = getToken();
    if (!token) {
      token = await ensureAuth();
    }
    if (!token) {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = setTimeout(connect, 3000);
      return;
    }

    let wsBase = process.env.NEXT_PUBLIC_WS_URL;
    if (!wsBase && typeof window !== 'undefined') {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      wsBase = `${proto}//${window.location.host}`;
    } else if (!wsBase) {
      wsBase = 'ws://localhost:8000';
    }
    const url = `${wsBase}/api/ws/live?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      setError(null);
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        const enrichedMsg = { ...msg, _ts: Date.now() };
        setLastMessage(enrichedMsg);
        setMessages((prev) => [
          enrichedMsg,
          ...prev.slice(0, maxMessages - 1),
        ]);

        // Dispatch globally on window for all listeners across pages
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('ids-live-event', { detail: enrichedMsg }));
        }
      } catch {
        // ignore non-JSON
      }
    };

    ws.onerror = () => setError('WebSocket connection error');

    ws.onclose = (e) => {
      setIsConnected(false);
      if (e.code !== 1000) {
        if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(connect, 5000);
      }
    };
  }, [maxMessages]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      wsRef.current?.close(1000, 'component unmounted');
    };
  }, [connect]);

  return { messages, lastMessage, isConnected, error };
}

/**
 * Hook to execute a callback whenever any live event (attack, alert, incident, IPS action, audit log) is broadcast.
 */
export function useOnLiveEvent(callback) {
  const cbRef = useRef(callback);
  cbRef.current = callback;

  // Also ensure WebSocket connection is established
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

