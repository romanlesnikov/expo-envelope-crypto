/**
 * The iteration count has to rise over the years, and raising it must not lock
 * anyone out. These are the tests for that: the stored count is the only one
 * that may be used to open a keyring, and an upgrade keeps the data readable.
 *
 * Skipping the stored count and deriving at the current default is a real bug
 * that ships easily — the code still works for everyone who signed up after
 * the change, so it only surfaces for existing users.
 */

import { describe, expect, it } from 'vitest'
import { WrongPasswordError } from '../src/core'
import { LEGACY_ITERATIONS, TEST_ITERATIONS, vaultAt } from './helpers'

const PASSWORD = 'correct horse battery staple'

/** Yesterday's app: keyrings written at the old, lower count. */
const oldVault = vaultAt(LEGACY_ITERATIONS)

/** Today's app: same data, higher default. */
const newVault = vaultAt(TEST_ITERATIONS)

describe('opening a keyring written before the count was raised', () => {
    it('derives at the count stored in the keyring, not the current default', async () => {
        const { keyring, key } = await oldVault.create(PASSWORD)

        expect(keyring.iterations).toBe(LEGACY_ITERATIONS)

        const opened = await newVault.open(keyring, PASSWORD)

        expect(Array.from(opened.key)).toEqual(Array.from(key))
    })

    it('reports that the keyring needs upgrading', async () => {
        const { keyring } = await oldVault.create(PASSWORD)

        expect((await newVault.open(keyring, PASSWORD)).needsUpgrade).toBe(true)
    })

    it('reports no upgrade needed once it is current', async () => {
        const { keyring } = await newVault.create(PASSWORD)

        expect((await newVault.open(keyring, PASSWORD)).needsUpgrade).toBe(false)
    })

    it('still refuses a wrong password', async () => {
        const { keyring } = await oldVault.create(PASSWORD)

        await expect(newVault.open(keyring, 'wrong')).rejects.toThrow(WrongPasswordError)
    })
})

describe('rewrap', () => {
    it('raises the stored count and takes a fresh salt', async () => {
        const { keyring } = await oldVault.create(PASSWORD)
        const { key } = await newVault.open(keyring, PASSWORD)

        const upgraded = await newVault.rewrap(key, PASSWORD)

        expect(upgraded.iterations).toBe(TEST_ITERATIONS)
        expect(upgraded.salt).not.toBe(keyring.salt)
        expect(upgraded.wrappedKey).not.toBe(keyring.wrappedKey)
    })

    it('keeps the data key byte for byte', async () => {
        const { keyring, key } = await oldVault.create(PASSWORD)
        const opened = await newVault.open(keyring, PASSWORD)
        const upgraded = await newVault.rewrap(opened.key, PASSWORD)

        const reopened = await newVault.open(upgraded, PASSWORD)

        expect(Array.from(reopened.key)).toEqual(Array.from(key))
        expect(reopened.needsUpgrade).toBe(false)
    })

    it('leaves data written before the upgrade readable afterwards', async () => {
        const { keyring, key } = await oldVault.create(PASSWORD)
        const packed = await oldVault.encrypt('balance: 42', key)

        const opened = await newVault.open(keyring, PASSWORD)
        const upgraded = await newVault.rewrap(opened.key, PASSWORD)
        const reopened = await newVault.open(upgraded, PASSWORD)

        expect(await newVault.decrypt(packed, reopened.key)).toBe('balance: 42')
    })

    it('does not change which password opens the keyring', async () => {
        const { keyring } = await oldVault.create(PASSWORD)
        const { key } = await newVault.open(keyring, PASSWORD)
        const upgraded = await newVault.rewrap(key, PASSWORD)

        await expect(newVault.open(upgraded, 'wrong')).rejects.toThrow(WrongPasswordError)
    })

    it('leaves the old keyring usable, so a failed upgrade is not a lockout', async () => {
        const { keyring } = await oldVault.create(PASSWORD)
        const { key } = await newVault.open(keyring, PASSWORD)

        await newVault.rewrap(key, PASSWORD)

        // The upgrade produces a new record; it does not mutate the old one.
        // If storing the new record fails, the caller still has this.
        const opened = await newVault.open(keyring, PASSWORD)

        expect(Array.from(opened.key)).toEqual(Array.from(key))
    })
})
