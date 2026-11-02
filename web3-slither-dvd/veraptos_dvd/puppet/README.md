# Puppet — spot oracle

## Before

```
collateral MUST NOT be derived from spot DEX reserve ratio (balance / balanceOf(pair))
```

## After

```
veraptos-puppet-spot-oracle
PuppetPool — spot Uniswap reserve ratio used as price oracle
```

Log: `test-logs/veraptos-puppet-spot-oracle.log`.

## Proof

DVD v3.0.0 **Puppet** — `_computeOraclePrice()` uses `uniswapPair.balance / token.balanceOf(uniswapPair)`.
