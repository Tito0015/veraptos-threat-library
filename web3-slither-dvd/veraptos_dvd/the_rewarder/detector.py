from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.utils.output import Output

from veraptos_dvd._helpers import _function_text, calls_snapshot_or_balance_of_at


class RewarderSnapshotManipulation(AbstractDetector):
    ARGUMENT = "veraptos-rewarder-snapshot-manipulation"
    HELP = "Reward distribution reads snapshot balances that can be manipulated in the same transaction"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://veraptos.dev/threat-library/rewarder"
    WIKI_TITLE = "Rewarder snapshot manipulation"
    WIKI_DESCRIPTION = "Deposit path triggers reward payout based on snapshot accounting in the same tx."
    WIKI_EXPLOIT_SCENARIO = "Flash-loan liquidity, deposit, and claim rewards within one transaction."
    WIKI_RECOMMENDATION = "Separate snapshot timing from deposits or use prior-round snapshots only."

    def _detect(self) -> list[Output]:
        outputs: list[Output] = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.name != "TheRewarderPool":
                continue
            deposit = next((f for f in contract.functions if f.name == "deposit"), None)
            distribute = contract.get_function_from_signature("distributeRewards()")
            if not deposit or not distribute:
                continue
            if not calls_snapshot_or_balance_of_at(distribute):
                continue
            calls_distribute = "distributeRewards" in _function_text(deposit) or any(
                getattr(ic, "function", None) and ic.function.name == "distributeRewards"
                for ic in deposit.all_internal_calls()
            )
            if not calls_distribute:
                continue
            info = [
                contract,
                " Rewarder: deposit/distributeRewards uses snapshot accounting with flash loan in compilation unit\n",
                deposit,
                distribute,
            ]
            outputs.append(self.generate_result(info))
        return outputs
