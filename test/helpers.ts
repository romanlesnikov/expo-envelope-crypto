import { createVault, type CryptoBackend } from '../src/core'

/**
 * Node has had WebCrypto built in since 16, and react-native-quick-crypto
 * implements the same SubtleCrypto surface — so the tests exercise the real
 * algorithms rather than a mock, and only the backend differs from production.
 */
export const nodeBackend: CryptoBackend = {
    subtle: globalThis.crypto.subtle,
    randomBytes: (length: number) => globalThis.crypto.getRandomValues(new Uint8Array(length)),
}

/**
 * Tests run at a deliberately low iteration count. The real default is asserted
 * once, in its own test, so the suite stays fast without hiding the number.
 */
export const TEST_ITERATIONS = 1_000
export const LEGACY_ITERATIONS = 500

export const vaultAt = (iterations: number) => createVault(nodeBackend, { iterations })

export const vault = vaultAt(TEST_ITERATIONS)
