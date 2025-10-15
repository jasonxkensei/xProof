// Polyfills required for @multiversx/sdk-dapp browser compatibility
// The SDK dependencies (sdk-core) require Node.js globals

if (typeof global === 'undefined') {
  (window as any).global = globalThis;
}

if (typeof process === 'undefined') {
  (window as any).process = {
    env: {},
    version: '',
    nextTick: (fn: Function) => setTimeout(fn, 0)
  };
}

export {};
