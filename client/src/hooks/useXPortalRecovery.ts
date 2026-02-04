import { useEffect, useState } from 'react';

const PENDING_CONNECTION_KEY = 'xportal_pending_connection';
const RECOVERY_EVENT = 'xportal:recovery:needed';

export interface PendingXPortalConnection {
  timestamp: number;
  returnUrl: string;
}

export function checkPendingXPortalConnection(): PendingXPortalConnection | null {
  try {
    const stored = localStorage.getItem(PENDING_CONNECTION_KEY);
    if (!stored) return null;
    
    const data = JSON.parse(stored) as PendingXPortalConnection;
    const elapsed = Date.now() - data.timestamp;
    const maxAge = 5 * 60 * 1000; // 5 minutes
    
    if (elapsed >= maxAge) {
      localStorage.removeItem(PENDING_CONNECTION_KEY);
      return null;
    }
    
    return data;
  } catch {
    localStorage.removeItem(PENDING_CONNECTION_KEY);
    return null;
  }
}

export function clearPendingXPortalConnection() {
  localStorage.removeItem(PENDING_CONNECTION_KEY);
}

export function savePendingXPortalConnection() {
  localStorage.setItem(PENDING_CONNECTION_KEY, JSON.stringify({
    timestamp: Date.now(),
    returnUrl: window.location.href,
  }));
}

export function useXPortalRecovery() {
  const [needsRecovery, setNeedsRecovery] = useState(false);
  const [pendingConnection, setPendingConnection] = useState<PendingXPortalConnection | null>(null);
  
  useEffect(() => {
    const pending = checkPendingXPortalConnection();
    if (pending) {
      console.log('📱 xPortal recovery: Detected pending connection from', new Date(pending.timestamp).toLocaleTimeString());
      setPendingConnection(pending);
      setNeedsRecovery(true);
    }
    
    const handleRecoveryEvent = () => {
      const pending = checkPendingXPortalConnection();
      if (pending) {
        setPendingConnection(pending);
        setNeedsRecovery(true);
      }
    };
    
    window.addEventListener(RECOVERY_EVENT, handleRecoveryEvent);
    return () => window.removeEventListener(RECOVERY_EVENT, handleRecoveryEvent);
  }, []);
  
  const clearRecovery = () => {
    clearPendingXPortalConnection();
    setNeedsRecovery(false);
    setPendingConnection(null);
  };
  
  return {
    needsRecovery,
    pendingConnection,
    clearRecovery,
  };
}

export function triggerXPortalRecoveryCheck() {
  window.dispatchEvent(new CustomEvent(RECOVERY_EVENT));
}
