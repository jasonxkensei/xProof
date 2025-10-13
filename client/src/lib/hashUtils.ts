// Utility to compute SHA-256 hash of a file client-side
export async function computeFileHash(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

// Format hash for display (truncate with ellipsis)
export function formatHash(hash: string, length: number = 16): string {
  if (hash.length <= length) return hash;
  const start = Math.floor(length / 2);
  const end = Math.ceil(length / 2);
  return `${hash.slice(0, start)}...${hash.slice(-end)}`;
}

// Copy to clipboard utility
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (err) {
    console.error('Failed to copy:', err);
    return false;
  }
}
