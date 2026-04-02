declare module "crypto" {
  interface Hash {
    update(data: string | Uint8Array, encoding?: string): Hash;
    digest(encoding: "hex"): string;
    digest(): Uint8Array;
  }
  function createHash(algorithm: string): Hash;
}

declare module "path" {
  function basename(path: string, ext?: string): string;
}

declare module "fs/promises" {
  function readFile(path: string): Promise<Uint8Array>;
}
