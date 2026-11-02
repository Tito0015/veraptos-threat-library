# The Rewarder — snapshot manipulation

## Before

```
deposit MUST NOT trigger distributeRewards that reads balanceOfAt
  on a snapshot taken in the same transaction path
```

## After

```
veraptos-rewarder-snapshot-manipulation
TheRewarderPool.deposit / distributeRewards — snapshot accounting
```

Log: `test-logs/veraptos-rewarder-snapshot-manipulation.log`.

## Proof

DVD v3.0.0 **The Rewarder** — flash-loaned liquidity, deposit, and reward claim in one tx via `AccountingToken` snapshots.
