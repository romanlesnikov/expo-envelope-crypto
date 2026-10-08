# expo-envelope-crypto

Password-protected envelope encryption for React Native and the web. AES-256-GCM for the data, PBKDF2-HMAC-SHA256 for the password, and a KDF iteration count you can raise later without locking anyone out.

```ts
import { vault } from 'expo-envelope-crypto'

// first run
const { keyring, key } = await vault.create(password)
await db.save(keyring)                            // safe to store in plain text
const row = await vault.encrypt('balance: 42', key)

// every run after that
const { key, needsUpgrade } = await vault.open(keyring, password)
const text = await vault.decrypt(row, key)

if (needsUpgrade) {
    await db.save(await vault.rewrap(key, password))
}
```

## Why an envelope

A random **data key** encrypts the data. That data key is itself encrypted with a **wrapping key** derived from the user's password, and only the wrapped form is ever stored. The password is never stored in any form.

The point is what happens when something about the password changes. Changing the password, or raising the iteration count, re-wraps a 32-byte key — the data is not touched. Derive the key straight from the password instead, and every one of those operations means re-encrypting the whole database.

## The iteration count has to move

PBKDF2 is only as good as its iteration count, and the number that was fine in 2020 is weak now. OWASP's floor for PBKDF2-HMAC-SHA256 is currently **210,000** and rises over time; this library creates new keyrings at **600,000**.

So a shipped app will, sooner or later, hold keyrings written at a lower count. The rule that makes that survivable:

> **A keyring is always opened with the iteration count stored in that keyring — never with the current default.**

Break that rule and the app still works perfectly for everyone who signed up after the change, which is exactly why the bug ships. Only existing users are locked out, and they cannot get back in.

`open()` reads `keyring.iterations`, reports `needsUpgrade`, and `rewrap()` produces a new keyring at the current count with a fresh salt. The data key is unchanged, so data written before the upgrade reads fine after it. Store the result; if storing fails, the old keyring is still valid and the upgrade retries on the next unlock.

## Install

Not on npm — install it from here:

```bash
npm install github:romanlesnikov/expo-envelope-crypto
```

On React Native it needs `react-native-quick-crypto` (WebCrypto does not exist on native) and `expo-crypto`. On the web it uses the platform's own `crypto` and needs neither.

## API

| | |
| --- | --- |
| `vault.create(password)` | New data key, wrapped. Returns `{ keyring, key }`. |
| `vault.open(keyring, password)` | Returns `{ key, needsUpgrade }`. Throws `WrongPasswordError`. |
| `vault.rewrap(key, password)` | New keyring at the current count, fresh salt, same data key. |
| `vault.changePassword(keyring, old, new)` | New keyring, same data key. Data untouched. |
| `vault.encrypt(text, key)` | base64 of `nonce ++ ciphertext` — one string to store. |
| `vault.decrypt(packed, key)` | Throws `CorruptedDataError` if it was modified or truncated. |

A `Keyring` is plain JSON — `{ version, salt, iterations, wrappedKey, wrapNonce }` — and holds nothing secret. Store it next to the data.

Every primitive comes from an injected backend, so `src/core.ts` has no platform imports at all. `index.ts` wires it to `react-native-quick-crypto`, `index.web.ts` to `window.crypto`, and you can supply your own:

```ts
import { createVault } from 'expo-envelope-crypto/core'

const vault = createVault(myBackend, { iterations: 600_000 })
```

## Tests

`npm test` — 26 cases, no mocks. Node has had WebCrypto built in since 16 and `react-native-quick-crypto` implements the same `SubtleCrypto` surface, so the suite runs the real algorithms and only the backend differs from production. Tests use a deliberately low iteration count for speed; the real default is asserted in a test of its own.

Beyond round-tripping, the suite covers the things that are quiet when they break:

- the same plaintext never encrypts to the same bytes twice — a reused nonce is catastrophic in GCM and invisible without this check
- a single flipped byte in the ciphertext is rejected, which is what proves authentication is actually on
- a keyring written at a lower iteration count still opens, the data key comes back byte for byte, and data written before an upgrade still decrypts after it
- the old keyring keeps working after `rewrap`, so a failed write is not a lockout

That last group was checked by introducing the bug it guards against: making `open()` use the current default instead of the stored count fails 7 of the 9 upgrade tests, while the rest of the suite stays green — the same shape the real bug has in production.

## What this does not do

- **No key stretching beyond PBKDF2.** OWASP ranks PBKDF2 last, after Argon2id and scrypt; it is here because it is what WebCrypto and `react-native-quick-crypto` both offer. If you can use Argon2id, use it.
- **No protection against a compromised device.** The data key lives in memory while the app is unlocked. This defends data at rest.
- **No password strength policy.** A weak password is a weak vault, whatever the iteration count.
- **600,000 iterations is not free.** On a low-end phone it is a noticeable pause at unlock. Measure it on the worst device you support before raising it further.

## License

MIT
