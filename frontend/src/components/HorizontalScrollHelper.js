'use client';

import { useEffect } from 'react';

/**
 * HorizontalScrollHelper
 * Ensures permanent, first-class horizontal mouse scroll across the entire platform:
 * 1. Mouse Wheel Horizontal Translation: Scrolling the mouse wheel while hovering over any
 *    table, radar, code block, or horizontally scrollable element scrolls horizontally.
 * 2. Boundary Stability: Prevents sudden jarring vertical jumps when rolling the mouse wheel over tables.
 * 3. Drag-to-Scroll: Allows clicking and dragging horizontally with the mouse pointer on tables and containers.
 * 4. Shift + Wheel: Holding Shift rolls horizontally anywhere across the viewport.
 */
export default function HorizontalScrollHelper() {
  useEffect(() => {
    // ── 1. Helper: Find nearest horizontally scrollable element ────────────
    const findHorizontalContainer = (targetEl) => {
      if (!targetEl) return null;
      let el = targetEl instanceof Element ? targetEl : targetEl.parentElement;
      if (!el) return null;

      // Check explicit class indicators first
      const explicit = el.closest('.table-wrapper, [data-horizontal-scroll="true"], .scroll-horizontal, .geo-radar-card, .workspace-nav-bar');
      if (explicit && explicit.scrollWidth - explicit.clientWidth > 2) {
        return explicit;
      }

      // Traverse up to find any container that has horizontal overflow
      let curr = el;
      let bestCandidate = null;

      while (curr && curr !== document.body && curr !== document.documentElement) {
        const overflow = curr.scrollWidth - curr.clientWidth;
        if (overflow > 2) {
          const style = window.getComputedStyle(curr);
          const ox = style.overflowX;
          if (ox === 'auto' || ox === 'scroll') {
            bestCandidate = curr;
            break;
          }
        }
        curr = curr.parentElement;
      }

      return bestCandidate || explicit || null;
    };

    // ── 2. Mouse Wheel Handler ─────────────────────────────────────────────
    const handleWheel = (e) => {
      // If native horizontal trackpad gesture (deltaX > deltaY) without Shift, allow browser native
      if (!e.shiftKey && Math.abs(e.deltaX) > Math.abs(e.deltaY)) {
        return;
      }

      // If user holds Ctrl (e.g. browser zoom), do not intercept
      if (e.ctrlKey) return;

      const container = findHorizontalContainer(e.target);
      if (!container) return;

      const maxScroll = container.scrollWidth - container.clientWidth;
      if (maxScroll <= 2) return;

      // Calculate scroll delta
      let delta = e.deltaY;
      if (e.shiftKey && Math.abs(e.deltaX) > 0) {
        delta = e.deltaX;
      }

      // Normalize delta mode
      if (e.deltaMode === 1) delta *= 28; // Lines
      else if (e.deltaMode === 2) delta *= 400; // Pages

      // Always intercept wheel events inside horizontal containers to guarantee permanent horizontal scrolling
      e.preventDefault();

      // Apply horizontal scroll with bounds clamping
      const currentScroll = container.scrollLeft;
      const targetScroll = Math.max(0, Math.min(currentScroll + delta, maxScroll));
      container.scrollLeft = targetScroll;
    };

    // ── 3. Mouse Drag-to-Scroll Handler (Left Button or Middle Button) ──────
    let isDragging = false;
    let startX = 0;
    let scrollStartLeft = 0;
    let dragContainer = null;

    const handleMouseDown = (e) => {
      // Allow drag on left click (button 0) or middle click (button 1)
      if (e.button !== 0 && e.button !== 1) return;

      // Don't hijack clicks on buttons, inputs, links, select, or text inputs
      const tag = e.target.tagName?.toLowerCase();
      if (['button', 'input', 'select', 'textarea', 'a'].includes(tag) || e.target.closest('button, a, input, select, textarea')) {
        return;
      }

      const container = findHorizontalContainer(e.target);
      if (!container) return;

      if (container.scrollWidth - container.clientWidth <= 2) return;

      isDragging = true;
      dragContainer = container;
      startX = e.clientX;
      scrollStartLeft = container.scrollLeft;
      container.style.cursor = 'grab';
      container.style.userSelect = 'none';
    };

    const handleMouseMove = (e) => {
      if (!isDragging || !dragContainer) return;
      e.preventDefault();
      const walk = (e.clientX - startX) * 1.5; // Smooth 1.5x drag ratio
      dragContainer.scrollLeft = scrollStartLeft - walk;
      dragContainer.style.cursor = 'grabbing';
    };

    const handleMouseUp = () => {
      if (isDragging && dragContainer) {
        dragContainer.style.cursor = '';
        dragContainer.style.userSelect = '';
      }
      isDragging = false;
      dragContainer = null;
    };

    // Attach listeners
    window.addEventListener('wheel', handleWheel, { passive: false });
    window.addEventListener('mousedown', handleMouseDown, { passive: true });
    window.addEventListener('mousemove', handleMouseMove, { passive: false });
    window.addEventListener('mouseup', handleMouseUp, { passive: true });

    return () => {
      window.removeEventListener('wheel', handleWheel);
      window.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);

  return null;
}
