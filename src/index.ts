/**
 * React Native entry point.
 *
 * WebCrypto does not exist on native, so `subtle` comes from
 * react-native-quick-crypto and the random bytes from expo-crypto.
 * The web build swaps this file for index.web.ts and uses the platform's own
 * crypto; everything above that line is shared.
 */

import { getRandomBytes } from 'expo-crypto'
import { subtle } from 'react-native-quick-crypto'
import { createVault, type CryptoBackend, type VaultOptions } from './core'

export const backend: CryptoBackend = {
    subtle: subtle as unknown as SubtleCrypto,
    randomBytes: (length: number) => new Uint8Array(getRandomBytes(length)),
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
