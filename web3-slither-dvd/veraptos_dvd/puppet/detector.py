from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.utils.output import Output

from veraptos_dvd._helpers import spot_price_division_in_contract


class PuppetSpotOracle(AbstractDetector):
    ARGUMENT = "veraptos-puppet-spot-oracle"
    HELP = "Collateral computed from DEX spot reserve ratio instead of TWAP"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://veraptos.dev/threat-library/puppet"
    WIKI_TITLE = "Puppet spot oracle"
    WIKI_DESCRIPTION = "Lending logic divides pair ETH balance by token balanceOf(pair)."
    WIKI_EXPLOIT_SCENARIO = "Manipulate Uniswap reserves in the same transaction to borrow undercollateralized."
    WIKI_RECOMMENDATION = "Use TWAP or oracle resistant to single-block manipulation."

    def _detect(self) -> list[Output]:
        outputs: list[Output] = []
        for contract in self.compilation_unit.contracts_derived:
            borrow = next((f for f in contract.functions if f.name == "borrow"), None)
            if not borrow:
                continue
            divisions = spot_price_division_in_contract(contract)
            if not divisions:
                src = contract.source_mapping.content if contract.source_mapping else ""
                if "balanceOf(uniswapPair)" not in src and "uniswapPair.balance" not in src:
                    continue
            info = [
                contract,
                " Puppet: spot Uniswap reserve ratio used as price oracle\n",
                borrow,
            ]
            outputs.append(self.generate_result(info))
        return outputs
