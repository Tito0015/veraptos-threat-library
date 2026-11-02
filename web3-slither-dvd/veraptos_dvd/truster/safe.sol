// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract SafeTrusterLenderPool {
    IERC20 public immutable token;

    error RepayFailed();

    constructor(IERC20 _token) {
        token = _token;
    }

    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
        external
        returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));
        token.transfer(borrower, amount);
        require(target == address(token), "target must be token");
        (bool ok,) = address(token).call(data);
        require(ok, "call failed");
        if (token.balanceOf(address(this)) < balanceBefore) revert RepayFailed();
        return true;
    }
}
