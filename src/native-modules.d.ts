/**
 * Minimal declarations for the two React Native packages `index.ts` wires up.
 *
 * They are optional peer dependencies: a web consumer never installs them, and
 * installing them here only to typecheck twenty lines of wiring would pull
 * expo, react and react-native into this package's CI. The trade-off is that
 * a change in their API is not caught by the compiler — which is why `core.ts`
 * takes its primitives as an injected backend and imports neither.
 */

declare module 'expo-crypto' {
    export function getRandomBytes(byteCount: number): Uint8Array
}

declare module 'react-native-quick-crypto' {
    export const subtle: SubtleCrypto
}
