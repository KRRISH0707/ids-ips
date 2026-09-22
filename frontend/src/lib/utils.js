/**
 * Shared utility functions used across the IDS/IPS platform.
 */

/**
 * Format a date/timestamp as a relative string ("2 min ago", "3 hrs ago")
 * with the full localized absolute time on hover via the `title` attribute.
 *
 * Usage:
 *   const { relative, absolute } = formatRelativeTime(log.created_at);
 *   <span title={absolute}>{relative}</span>
 */
export function formatRelativeTime(dateInput) {
  if (!dateInput) return { relative: '—', absolute: '—' };

  const date = dateInput instanceof Date ? dateInput : new Date(dateInput);
  if (isNaN(date.getTime())) return { relative: String(dateInput), absolute: String(dateInput) };

  const absolute = date.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });

  const diffMs = Date.now() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHr = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHr / 24);

  let relative;
  if (diffSec < 10) {
    relative = 'just now';
  } else if (diffSec < 60) {
    relative = `${diffSec}s ago`;
  } else if (diffMin < 60) {
    relative = `${diffMin} min ago`;
  } else if (diffHr < 24) {
    relative = `${diffHr} hr${diffHr > 1 ? 's' : ''} ago`;
  } else if (diffDay < 7) {
    relative = `${diffDay} day${diffDay > 1 ? 's' : ''} ago`;
  } else {
    relative = date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  }

  return { relative, absolute };
}

/**
 * Export a flat array of objects to a CSV file download.
 *
 * @param {Object[]} rows         - Array of row objects
 * @param {string[]} columns      - Keys to include (in order)
 * @param {string[]} headers      - Display headers matching columns
 * @param {string}   filename     - Output filename (e.g. "alerts_export.csv")
 */
export function exportToCSV(rows, columns, headers, filename = 'export.csv') {
  if (!rows || rows.length === 0) return;

  const escape = (val) => {
    const str = val === null || val === undefined ? '' : String(val);
    // Wrap in quotes if contains comma, quote, or newline
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const headerRow = headers.map(escape).join(',');
  const dataRows = rows.map((row) =>
    columns.map((col) => escape(row[col])).join(',')
  );

  const csvContent = [headerRow, ...dataRows].join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
