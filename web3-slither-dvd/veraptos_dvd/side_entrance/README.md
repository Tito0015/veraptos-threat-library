# Side Entrance — state hijack

## Before

```
IF flashLoan repays using address(this).balance
THEN deposit() MUST NOT credit internal balances during the callback
```

## After

```
veraptos-side-entrance-state-hijack
SideEntranceLenderPool — flashLoan + payable deposit() writing balances
```

Log: `test-logs/veraptos-side-entrance-state-hijack.log`.

## Proof

DVD v3.0.0 **Side Entrance** — callback to `msg.sender.execute()` while `deposit()` inflates `balances[msg.sender]` before the ETH balance check passes.
