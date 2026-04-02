declare module "crypto" {
  interface Hash {
    update(data: string | Buffer | Uint8Array, encoding?: string): Hash;
    digest(encoding: "hex"): string;
    digest(): Buffer;
  }
  function createHash(algorithm: string): Hash;
}

declare module "path" {
  function basename(path: string, ext?: string): string;
}

declare module "fs/promises" {
  function readFile(path: string): Promise<Buffer>;
}
