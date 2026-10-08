/**
 * Web entry point. Metro and most bundlers pick this file over index.ts for
 * the web target, so the browser's own WebCrypto is used and no polyfill ships.
 */

import { createVault, type CryptoBackend, type VaultOptions } from './core'

export const backend: CryptoBackend = {
    subtle: globalThis.crypto.subtle,
    randomBytes: (length: number) => globalThis.crypto.getRandomValues(new Uint8Array(length)),
}

export const vault = createVault(backend)

export function createVaultWith(options: VaultOptions) {
    return createVault(backend, options)
}

export {
    createVault,
    CorruptedDataError,
    DEFAULT_ITERATIONS,
    MIN_ITERATIONS,
    WrongPasswordError,
} from './core'

export type { CryptoBackend, Keyring, OpenedKeyring, Vault, VaultOptions } from './core'
