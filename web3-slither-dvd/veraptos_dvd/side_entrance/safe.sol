// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashLoanEtherReceiver {
    function execute() external payable;
}

contract SafeSideEntranceLenderPool {
    mapping(address => uint256) private balances;
    uint256 private _flashDebt;

    error RepayFailed();

    function deposit() external payable {
        require(_flashDebt == 0, "no deposit during flash loan");
        balances[msg.sender] += msg.value;
    }

    function flashLoan(uint256 amount) external {
        uint256 debt = amount;
        _flashDebt = debt;
        IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
        _flashDebt = 0;
        if (address(this).balance < amount) revert RepayFailed();
    }
}
