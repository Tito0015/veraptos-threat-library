from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.utils.output import Output

from veraptos_dvd._helpers import (
    external_callback_to_sender,
    function_has_balance_repay_check,
    is_publicly_callable,
    mapping_balance_writes,
)
from veraptos_dvd._helpers import _function_text
from veraptos_dvd.truster.detector import _has_target_token_guard


class SideEntranceStateHijack(AbstractDetector):
    ARGUMENT = "veraptos-side-entrance-state-hijack"
    HELP = "Flash loan repaid via ETH balance while deposit credits internal ledger during callback"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://veraptos.dev/threat-library/side-entrance"
    WIKI_TITLE = "Side entrance state hijack"
    WIKI_DESCRIPTION = "Pool accepts flash loan repayment via contract balance but allows deposit during callback."
    WIKI_EXPLOIT_SCENARIO = "Borrower re-enters deposit() in execute() to credit balances without paying ETH."
    WIKI_RECOMMENDATION = "Track flash-loan debt separately or block deposit during flash loan."

    def _detect(self) -> list[Output]:
        outputs: list[Output] = []
        for contract in self.compilation_unit.contracts_derived:
            flash = contract.get_function_from_signature("flashLoan(uint256)")
            if not flash:
                flash = next((f for f in contract.functions if f.name == "flashLoan"), None)
            deposit = contract.get_function_from_signature("deposit()")
            if not flash or not deposit:
                continue
            if not deposit.payable or not is_publicly_callable(deposit):
                continue
            if not mapping_balance_writes(deposit):
                continue
            if not function_has_balance_repay_check(flash):
                continue
            if not external_callback_to_sender(flash):
                continue
            dep_text = _function_text(deposit)
            if "_flashDebt" in dep_text or "during flash" in dep_text.lower():
                continue
            if "nonReentrant" in dep_text and "nonReentrant" in _function_text(flash):
                continue
            info = [
                contract,
                " Side entrance: flashLoan + payable deposit() writing balances with ETH balance check\n",
                flash,
                deposit,
            ]
            outputs.append(self.generate_result(info))
        return outputs
