// Polyfills for MultiversX SDK browser compatibility
if (typeof global === 'undefined') {
  (window as any).global = window;
}

export {};
