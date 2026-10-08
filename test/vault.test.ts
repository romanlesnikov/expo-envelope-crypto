import { describe, expect, it } from 'vitest'
import {
    CorruptedDataError,
    DEFAULT_ITERATIONS,
    MIN_ITERATIONS,
    WrongPasswordError,
    createVault,
} from '../src/core'
import { TEST_ITERATIONS, nodeBackend, vault } from './helpers'

const PASSWORD = 'correct horse battery staple'

describe('defaults', () => {
    it('creates keyrings above the OWASP floor', () => {
        expect(DEFAULT_ITERATIONS).toBeGreaterThanOrEqual(MIN_ITERATIONS)
        expect(createVault(nodeBackend).iterations).toBe(DEFAULT_ITERATIONS)
    })
})

describe('encrypt / decrypt', () => {
    it('round-trips text', async () => {
        const { key } = await vault.create(PASSWORD)

        expect(await vault.decrypt(await vault.encrypt('hello', key), key)).toBe('hello')
    })

    it('round-trips an empty string', async () => {
        const { key } = await vault.create(PASSWORD)

        expect(await vault.decrypt(await vault.encrypt('', key), key)).toBe('')
    })

    it('round-trips non-latin text and emoji', async () => {
        const { key } = await vault.create(PASSWORD)
        const text = 'Привет 🔐 日本語 — ok'

        expect(await vault.decrypt(await vault.encrypt(text, key), key)).toBe(text)
    })

    it('round-trips a payload larger than one block', async () => {
        const { key } = await vault.create(PASSWORD)
        const text = 'x'.repeat(100_000)

        expect(await vault.decrypt(await vault.encrypt(text, key), key)).toBe(text)
    })

    it('never reuses a nonce, so the same plaintext encrypts differently each time', async () => {
        const { key } = await vault.create(PASSWORD)
        const results = await Promise.all(
            Array.from({ length: 20 }, () => vault.encrypt('same', key)),
        )

        expect(new Set(results).size).toBe(20)
    })

    it('rejects ciphertext that was modified', async () => {
        const { key } = await vault.create(PASSWORD)
        const packed = await vault.encrypt('transfer 100', key)
        const bytes = Uint8Array.from(atob(packed), char => char.charCodeAt(0))

        bytes[bytes.length - 1] = (bytes.at(-1) ?? 0) ^ 0x01

        const tampered = btoa(String.fromCharCode(...bytes))

        await expect(vault.decrypt(tampered, key)).rejects.toThrow(CorruptedDataError)
    })

    it('rejects ciphertext that is too short to hold a nonce', async () => {
        const { key } = await vault.create(PASSWORD)

        await expect(vault.decrypt(btoa('short'), key)).rejects.toThrow(CorruptedDataError)
    })

    it('cannot be decrypted with a different data key', async () => {
        const first = await vault.create(PASSWORD)
        const second = await vault.create(PASSWORD)
        const packed = await vault.encrypt('secret', first.key)

        await expect(vault.decrypt(packed, second.key)).rejects.toThrow(CorruptedDataError)
    })
})

describe('keyring', () => {
    it('opens with the right password and returns the same data key', async () => {
        const { keyring, key } = await vault.create(PASSWORD)
        const opened = await vault.open(keyring, PASSWORD)

        expect(Array.from(opened.key)).toEqual(Array.from(key))
    })

    it('refuses the wrong password', async () => {
        const { keyring } = await vault.create(PASSWORD)

        await expect(vault.open(keyring, 'wrong')).rejects.toThrow(WrongPasswordError)
    })

    it('uses a fresh salt every time, so the same password yields different keyrings', async () => {
        const first = await vault.create(PASSWORD)
        const second = await vault.create(PASSWORD)

        expect(first.keyring.salt).not.toBe(second.keyring.salt)
        expect(first.keyring.wrappedKey).not.toBe(second.keyring.wrappedKey)
    })

    it('records the iteration count it was created with', async () => {
        const { keyring } = await vault.create(PASSWORD)

        expect(keyring.iterations).toBe(TEST_ITERATIONS)
        expect(keyring.version).toBe(1)
    })

    it('stores no trace of the password or the data key', async () => {
        const { keyring, key } = await vault.create(PASSWORD)
        const serialised = JSON.stringify(keyring)

        expect(serialised).not.toContain(PASSWORD)
        expect(serialised).not.toContain(btoa(String.fromCharCode(...key)))
    })
})

describe('changePassword', () => {
    it('keeps the data key, so stored data does not need re-encrypting', async () => {
        const { keyring, key } = await vault.create(PASSWORD)
        const packed = await vault.encrypt('balance: 42', key)

        const updated = await vault.changePassword(keyring, PASSWORD, 'new password')
        const opened = await vault.open(updated, 'new password')

        expect(Array.from(opened.key)).toEqual(Array.from(key))
        expect(await vault.decrypt(packed, opened.key)).toBe('balance: 42')
    })

    it('stops accepting the old password', async () => {
        const { keyring } = await vault.create(PASSWORD)
        const updated = await vault.changePassword(keyring, PASSWORD, 'new password')

        await expect(vault.open(updated, PASSWORD)).rejects.toThrow(WrongPasswordError)
    })

    it('refuses to change the password when the old one is wrong', async () => {
        const { keyring } = await vault.create(PASSWORD)

        await expect(vault.changePassword(keyring, 'wrong', 'new')).rejects.toThrow(WrongPasswordError)
    })
})
