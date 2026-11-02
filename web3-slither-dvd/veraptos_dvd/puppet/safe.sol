// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface ITwap {
    function observe(uint32[] calldata secondsAgos) external view returns (int56[] memory);
}

contract SafePuppetPool {
    ITwap public twap;
    IERC20 public token;

    constructor(ITwap _twap, IERC20 _token) {
        twap = _twap;
        token = _token;
    }

    function borrow(uint256 amount) external payable {
        uint256 price = _twapPrice();
        uint256 required = amount * price * 2 / 1e18;
        require(msg.value >= required, "collateral");
        token.transfer(msg.sender, amount);
    }

    function _twapPrice() private view returns (uint256) {
        int56[] memory tickCumulatives = twap.observe(new uint32[](1));
        return uint256(int256(tickCumulatives[0]));
    }
}
