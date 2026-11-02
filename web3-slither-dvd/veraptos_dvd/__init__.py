"""Veraptos Threat Library — Slither plugin for Damn Vulnerable DeFi patterns."""


def make_plugin():
    from veraptos_dvd.puppet.detector import PuppetSpotOracle
    from veraptos_dvd.selfie.detector import SelfieGovernanceSnapshot
    from veraptos_dvd.side_entrance.detector import SideEntranceStateHijack
    from veraptos_dvd.the_rewarder.detector import RewarderSnapshotManipulation
    from veraptos_dvd.truster.detector import TrusterArbitraryCall

    detectors = [
        TrusterArbitraryCall,
        SideEntranceStateHijack,
        RewarderSnapshotManipulation,
        PuppetSpotOracle,
        SelfieGovernanceSnapshot,
    ]
    return detectors, []
