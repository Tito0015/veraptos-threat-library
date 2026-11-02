# Truster — arbitrary call

## Before (invariant)

```
flashLoan MUST NOT call target.functionCall(data)
  UNLESS target == address(token)
```

## After (Slither)

```
veraptos-truster-arbitrary-call
TrusterLenderPool.flashLoan(...)
  flashLoan allows arbitrary call to user-supplied target (Truster pattern)
```

See `test-logs/veraptos-truster-arbitrary-call.log`.

## Proof

Damn Vulnerable DeFi **v3.0.0** — **Truster** (`TrusterLenderPool.sol`). Pin: `33120e97e9dbe8c297496a99549e6408a3944e95`.

Borrower passes a malicious `target` and calldata that invokes `approve` on the real token, draining the pool.
