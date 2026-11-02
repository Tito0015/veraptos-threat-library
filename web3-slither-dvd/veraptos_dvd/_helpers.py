"""Shared helpers for Veraptos DVD Slither detectors."""

from __future__ import annotations

from slither.core.declarations import Contract, Function, SolidityVariable
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Binary, BinaryType, HighLevelCall, InternalCall, LibraryCall, LowLevelCall


def is_publicly_callable(function: Function) -> bool:
    return function.visibility in ("public", "external")


def contract_named(contract: Contract, *names: str) -> bool:
    return contract.name in names


def function_has_balance_repay_check(function: Function) -> bool:
    text = function.source_mapping.content if function.source_mapping else ""
    if "balanceBefore" in text and "balance" in text:
        return True
    for node in function.nodes:
        for ir in node.irs:
            if "balance" in str(ir).lower():
                return True
    return False


def mapping_balance_writes(function: Function) -> list:
    hits = []
    for node in function.nodes:
        for ir in node.irs:
            if hasattr(ir, "lvalue") and isinstance(getattr(ir, "lvalue", None), StateVariable):
                sv = ir.lvalue
                if "balance" in sv.name.lower():
                    hits.append(node)
            ir_text = str(ir)
            if "balances" in ir_text and "Write" in type(ir).__name__:
                hits.append(node)
        text = node.source_mapping.content if node.source_mapping else ""
        if "balances[" in text and "+=" in text:
            hits.append(node)
    return hits


def _function_text(function) -> str:
    chunks = []
    if function.source_mapping and function.source_mapping.content:
        chunks.append(function.source_mapping.content)
    for node in function.nodes:
        if node.source_mapping and node.source_mapping.content:
            chunks.append(node.source_mapping.content)
    return "\n".join(chunks)


def calls_snapshot_or_balance_of_at(function: Function) -> bool:
    text = _function_text(function)
    if any(k in text for k in ("balanceOfAt", "totalSupplyAt", "getBalanceAtLastSnapshot", "snapshot(")):
        return True
    sigs = (
        "snapshot()",
        "balanceOfAt(address,uint256)",
        "totalSupplyAt(uint256)",
        "getBalanceAtLastSnapshot(address)",
        "getTotalSupplyAtLastSnapshot()",
    )
    for _, ir in function.high_level_calls:
        if isinstance(ir, HighLevelCall) and isinstance(ir.function, Function):
            if ir.function.solidity_signature in sigs or ir.function.name in (
                "snapshot",
                "balanceOfAt",
                "totalSupplyAt",
                "getBalanceAtLastSnapshot",
            ):
                return True
    for ir in function.internal_calls + function.library_calls:
        callee = None
        if isinstance(ir, (InternalCall, LibraryCall)):
            callee = ir.function
        if isinstance(callee, Function) and callee.name in ("_recordSnapshot", "distributeRewards"):
            if callee.name == "_recordSnapshot":
                return True
    return False


def unit_has_flash_loan(compilation_unit) -> bool:
    for contract in compilation_unit.contracts_derived:
        if contract.name in ("FlashLoanerPool", "SelfiePool", "TrusterLenderPool"):
            return True
        for f in contract.functions:
            if f.name in ("flashLoan", "flash") and is_publicly_callable(f):
                return True
    return False


def spot_price_division_in_contract(contract: Contract) -> list[tuple[Function, object]]:
    """Return (function, ir) for spot-style reserve ratio divisions."""
    findings = []
    for function in contract.functions:
        for node in function.nodes:
            for ir in node.irs:
                if not isinstance(ir, Binary) or ir.type != BinaryType.DIVISION:
                    continue
                if _operands_look_like_spot_ratio(ir):
                    findings.append((function, node))
    return findings


def _operands_look_like_spot_ratio(ir: Binary) -> bool:
    left, right = ir.variable_left, ir.variable_right

    def subtree_has_balance_or_balanceof(v) -> bool:
        if v is None:
            return False
        vstr = str(v).lower()
        return "balance" in vstr

    return subtree_has_balance_or_balanceof(left) and subtree_has_balance_or_balanceof(right)


def external_callback_to_sender(function: Function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, HighLevelCall):
                if ir.function and ir.function.name == "execute":
                    return True
            if isinstance(ir, LowLevelCall):
                return True
    src = function.source_mapping.content if function.source_mapping else ""
    return "msg.sender" in src and "execute" in src
