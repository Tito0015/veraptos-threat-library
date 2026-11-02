from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import LibraryCall, LowLevelCall
from slither.utils.output import Output

from veraptos_dvd._helpers import _function_text, is_publicly_callable


def _has_target_token_guard(function, target_name: str = "target") -> bool:
    text = _function_text(function).replace(" ", "")
    return (
        f"{target_name}==address(token)" in text
        or f"address(token)=={target_name}" in text
        or f"{target_name}!=address(token)" in text
        or "require(target==address(token" in text
    )


class TrusterArbitraryCall(AbstractDetector):
    ARGUMENT = "veraptos-truster-arbitrary-call"
    HELP = "Flash loan executes arbitrary target.functionCall without verifying target is the token"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://veraptos.dev/threat-library/truster"
    WIKI_TITLE = "Truster arbitrary call"
    WIKI_DESCRIPTION = "Flash loan passes user-controlled target and calldata to Address.functionCall."
    WIKI_EXPLOIT_SCENARIO = "Approve hijacking on an arbitrary ERC20 via malicious calldata."
    WIKI_RECOMMENDATION = "Disallow arbitrary calls or restrict target to the loan token contract."

    def _detect(self) -> list[Output]:
        outputs: list[Output] = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.name != "flashLoan" or not is_publicly_callable(function):
                    continue
                params = {p.name: p for p in function.parameters}
                target_param = params.get("target")
                if not target_param:
                    continue
                if _has_target_token_guard(function):
                    continue
                hit_node = None
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, LibraryCall) and ir.function.name == "functionCall":
                            if len(ir.arguments) >= 1 and is_dependent(
                                ir.arguments[0], target_param, node
                            ):
                                hit_node = node
                        elif isinstance(ir, LowLevelCall) and is_dependent(
                            ir.destination, target_param, node
                        ):
                            if not _has_target_token_guard(function):
                                hit_node = node
                if hit_node:
                    info = [
                        contract,
                        " flashLoan allows arbitrary call to user-supplied target (Truster pattern)\n",
                        function,
                        hit_node,
                    ]
                    outputs.append(self.generate_result(info))
        return outputs
