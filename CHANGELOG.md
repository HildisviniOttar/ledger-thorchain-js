# 0.1.0 (2021-XX-XX)

## Update

- Rewrite in TypeScript
- Introduce custom `LedgerError`
- Improve `Promise` handling

## Breaking changes

- Values of misc. `XYZResponse`'s have been renamed to use camel case (instead of snake case)
- Re-organize helper function to be available in `helpers` and `common` only (Deprecated `v1` helpers have been removed)
- Rename some methods of THORChain app (mostly to prefix getter methods with `get...`)

# 0.0.3 (2021-07-20)

## Internal updates

- Update dependencies, Remove deprecated `@ledgerhq/hw-transport-u2f` from examples, Use same `jest.setTimeout` for all `e2e` tests [#2](https://github.com/thorchain/ledger-thorchain-js/pull/2)
- Update tests [#1](https://github.com/thorchain/ledger-thorchain-js/pull/1)

# 0.0.2 (2021-06-30)

Initial release
