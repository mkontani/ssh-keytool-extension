// Minimal typings for bcrypt-pbkdf (no @types package exists).
declare module 'bcrypt-pbkdf' {
    /** OpenBSD bcrypt_pbkdf(3). Writes `keylen` bytes into `key`; returns 0 on success, -1 on error. */
    export function pbkdf(
        pass: Uint8Array,
        passlen: number,
        salt: Uint8Array,
        saltlen: number,
        key: Uint8Array,
        keylen: number,
        rounds: number,
    ): number;

    const bcryptPbkdf: { pbkdf: typeof pbkdf };
    export default bcryptPbkdf;
}
