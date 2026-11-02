# Selfie — governance snapshot

## Before

```
queueAction MUST NOT rely on getBalanceAtLastSnapshot
  WHEN token.snapshot() is public and flash loans supply votes in the same tx
```

## After

```
veraptos-selfie-governance-snapshot
SimpleGovernance + DamnValuableTokenSnapshot.snapshot() + SelfiePool.flashLoan
```

Log: `test-logs/veraptos-selfie-governance-snapshot.log`.

## Proof

DVD v3.0.0 **Selfie** — flash loan governance tokens, `snapshot()`, then `queueAction` with majority weight.
