from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.utils.output import Output

from veraptos_dvd._helpers import is_publicly_callable


class SelfieGovernanceSnapshot(AbstractDetector):
    ARGUMENT = "veraptos-selfie-governance-snapshot"
    HELP = "Governance vote check uses snapshot that can be taken via public snapshot() before queueAction"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://veraptos.dev/threat-library/selfie"
    WIKI_TITLE = "Selfie governance snapshot"
    WIKI_DESCRIPTION = "queueAction reads last snapshot balance while token.snapshot() is public and flash loans exist."
    WIKI_EXPLOIT_SCENARIO = "Flash loan tokens, snapshot(), queueAction in one transaction."
    WIKI_RECOMMENDATION = "Restrict snapshot() or delay vote weight to prior blocks."

    def _detect(self) -> list[Output]:
        outputs: list[Output] = []
        governance = None
        token = None
        pool = None
        for contract in self.compilation_unit.contracts_derived:
            if contract.name == "SimpleGovernance":
                governance = contract
            if contract.name == "DamnValuableTokenSnapshot":
                token = contract
            if contract.name == "SelfiePool":
                pool = contract
        if not governance or not token or not pool:
            return outputs
        queue = governance.get_function_from_signature("queueAction(address,uint128,bytes)")
        snap_fn = token.get_function_from_signature("snapshot()")
        flash = pool.get_function_from_signature(
            "flashLoan(address,address,uint256,bytes)"
        ) or pool.get_function_from_signature(
            "flashLoan(contract IERC3156FlashBorrower,address,uint256,bytes)"
        )
        if not queue or not snap_fn or not flash:
            flash = next((f for f in pool.functions if f.name == "flashLoan"), None)
        if not queue or not snap_fn or not flash:
            return outputs
        if not snap_fn or not is_publicly_callable(snap_fn):
            return outputs
        gov_src = governance.source_mapping.content if governance.source_mapping else ""
        if "getBalanceAtLastSnapshot" not in gov_src:
            return outputs
        info = [
            governance,
            " Selfie: public snapshot() + queueAction vote check + ERC3156 flash loan\n",
            queue,
            snap_fn,
            flash,
        ]
        outputs.append(self.generate_result(info))
        return outputs
