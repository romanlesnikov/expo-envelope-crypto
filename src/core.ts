/**
 * Envelope encryption over AES-256-GCM.
 *
 * A random data key encrypts the data. That data key is itself encrypted with
 * a key derived from the user's password, and only the wrapped form is stored.
 * Changing the password re-wraps the data key, so the data is never re-encrypted.
 *
 * Every primitive comes from the backend passed in, so the same code runs on
 * React Native (react-native-quick-crypto) and on the web (window.crypto).
 */

/** OWASP's floor for PBKDF2-HMAC-SHA256. It rises over time; this is a lower bound, not a target. */
export const MIN_ITERATIONS = 210_000

/** What new keyrings are created with. */
export const DEFAULT_ITERATIONS = 600_000

const KEY_LENGTH = 32
const SALT_LENGTH = 32
const NONCE_LENGTH = 12

export interface CryptoBackend {
    subtle: SubtleCrypto
    randomBytes(length: number): Uint8Array | Promise<Uint8Array>
}

/**
 * Everything needed to recover the data key from a password. Safe to store in
 * plain text next to the data: without the password it reveals nothing.
 */
export interface Keyring {
    version: 1
    /** base64 */
    salt: string
    /** The iteration count this keyring's wrapped key was derived with. */
    iterations: number
    /** base64 — the data key, encrypted with the password-derived key. */
    wrappedKey: string
    /** base64 */
    wrapNonce: string
}

export interface OpenedKeyring {
    /** The data key. Keep it in memory; never store it. */
    key: Uint8Array
    /**
     * True when this keyring was derived with fewer iterations than the current
     * default — open it, then call `rewrap` and store the result.
     */
    needsUpgrade: boolean
}

export class WrongPasswordError extends Error {
    constructor() {
        super('Wrong password, or the keyring is corrupted')
        this.name = 'WrongPasswordError'
    }
}

export class CorruptedDataError extends Error {
    constructor() {
        super('Ciphertext failed authentication — it was truncated or modified')
        this.name = 'CorruptedDataError'
    }
}

function toBase64(bytes: Uint8Array): string {
    let binary = ''

    for (let index = 0; index < bytes.length; index++) {
        binary += String.fromCharCode(bytes[index]!)
    }

    return btoa(binary)
}

function fromBase64(value: string): Uint8Array {
    const binary = atob(value)
    const bytes = new Uint8Array(binary.length)

    for (let index = 0; index < binary.length; index++) {
        bytes[index] = binary.charCodeAt(index)
    }

    return bytes
}

export interface VaultOptions {
    /** Iteration count for new and re-wrapped keyrings. Defaults to DEFAULT_ITERATIONS. */
    iterations?: number
}

export function createVault(backend: CryptoBackend, options: VaultOptions = {}) {
    const defaultIterations = options.iterations ?? DEFAULT_ITERATIONS
    const { subtle } = backend

    const random = async (length: number) => Uint8Array.from(await backend.randomBytes(length))

    /** PBKDF2-HMAC-SHA256. The iteration count always comes from the caller, never from a constant. */
    const deriveWrappingKey = async (password: string, salt: Uint8Array, iterations: number) => {
        const material = await subtle.importKey(
            'raw',
            new TextEncoder().encode(password) as BufferSource,
            'PBKDF2',
            false,
            ['deriveBits'],
        )

        const bits = await subtle.deriveBits(
            { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
            material,
            KEY_LENGTH * 8,
        )

        return new Uint8Array(bits)
    }

    const importAesKey = (raw: Uint8Array, usage: KeyUsage[]) =>
        subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, false, usage)

    /** Creates a fresh data key and wraps it with the password. */
    const create = async (password: string): Promise<{ keyring: Keyring; key: Uint8Array }> => {
        const key = await random(KEY_LENGTH)
        const keyring = await wrap(key, password, defaultIterations)

        return { keyring, key }
    }

    const wrap = async (key: Uint8Array, password: string, iterations: number): Promise<Keyring> => {
        const salt = await random(SALT_LENGTH)
        const nonce = await random(NONCE_LENGTH)
        const wrappingKey = await importAesKey(
            await deriveWrappingKey(password, salt, iterations),
            ['encrypt'],
        )

        const wrapped = await subtle.encrypt(
            { name: 'AES-GCM', iv: nonce as BufferSource },
            wrappingKey,
            key as BufferSource,
        )

        return {
            version: 1,
            salt: toBase64(salt),
            iterations,
            wrappedKey: toBase64(new Uint8Array(wrapped)),
            wrapNonce: toBase64(nonce),
        }
    }

    /**
     * Recovers the data key. The iteration count is read from the keyring, so a
     * record written under an older setting still opens.
     */
    const open = async (keyring: Keyring, password: string): Promise<OpenedKeyring> => {
        const wrappingKey = await importAesKey(
            await deriveWrappingKey(password, fromBase64(keyring.salt), keyring.iterations),
            ['decrypt'],
        )

        try {
            const key = await subtle.decrypt(
                { name: 'AES-GCM', iv: fromBase64(keyring.wrapNonce) as BufferSource },
                wrappingKey,
                fromBase64(keyring.wrappedKey) as BufferSource,
            )

            return {
                key: new Uint8Array(key),
                needsUpgrade: keyring.iterations < defaultIterations,
            }
        } catch {
            throw new WrongPasswordError()
        }
    }

    /**
     * Re-wraps an already-opened data key with a fresh salt at the current
     * iteration count. The data key does not change, so nothing needs re-encrypting.
     */
    const rewrap = (key: Uint8Array, password: string) => wrap(key, password, defaultIterations)

    /** Same data key, new password. The data is never touched. */
    const changePassword = async (keyring: Keyring, oldPassword: string, newPassword: string) => {
        const { key } = await open(keyring, oldPassword)

        return wrap(key, newPassword, defaultIterations)
    }

    /** Returns base64 of nonce ++ ciphertext, so one string is all the caller stores. */
    const encrypt = async (plaintext: string, key: Uint8Array): Promise<string> => {
        const nonce = await random(NONCE_LENGTH)
        const aesKey = await importAesKey(key, ['encrypt'])

        const ciphertext = await subtle.encrypt(
            { name: 'AES-GCM', iv: nonce as BufferSource },
            aesKey,
            new TextEncoder().encode(plaintext) as BufferSource,
        )

        const packed = new Uint8Array(nonce.length + ciphertext.byteLength)

        packed.set(nonce, 0)
        packed.set(new Uint8Array(ciphertext), nonce.length)

        return toBase64(packed)
    }

    const decrypt = async (packed: string, key: Uint8Array): Promise<string> => {
        const bytes = fromBase64(packed)

        if (bytes.length <= NONCE_LENGTH) {
            throw new CorruptedDataError()
        }

        const aesKey = await importAesKey(key, ['decrypt'])

        try {
            const plaintext = await subtle.decrypt(
                { name: 'AES-GCM', iv: bytes.slice(0, NONCE_LENGTH) as BufferSource },
                aesKey,
                bytes.slice(NONCE_LENGTH) as BufferSource,
            )

            return new TextDecoder().decode(plaintext)
        } catch {
            throw new CorruptedDataError()
        }
    }

    return { create, open, rewrap, changePassword, encrypt, decrypt, iterations: defaultIterations }
}

export type Vault = ReturnType<typeof createVault>
