// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract PartyBridge is ERC20, Ownable {
    uint256 private _cap;
    uint256 private _dailyMintCap;
    mapping(address => uint256) private _lastMintTimestamp;
    mapping(address => uint256) private _dailyMintedAmounts;

    event CapSet(uint256 cap);
    event DailyCapSet(uint256 dailyMintCap);

    constructor(string memory name, string memory symbol, uint256 initialCap, uint256 initialDailyMintCap) ERC20(name, symbol) {
        require(initialCap > 0, "initialCap must be > 0");
        require(initialDailyMintCap > 0, "initialDailyMintCap must be > 0");
        _cap = initialCap;
        _dailyMintCap = initialDailyMintCap;
    }

    function cap() external view returns (uint256) {
        return _cap;
    }

    function dailyMintCap() external view returns (uint256) {
        return _dailyMintCap;
    }

    function lastMintTimestamp(address account) external view returns (uint256) {
        return _lastMintTimestamp[account];
    }

    function dailyMintedAmount(address account) external view returns (uint256) {
        return _dailyMintedAmounts[account];
    }

    function mint(address account, uint256 amount) external onlyOwner {
        // Reset the daily minted amount if a day has passed
        if (block.timestamp > _lastMintTimestamp[account] + 1 days) {
            _dailyMintedAmounts[account] = 0;
            _lastMintTimestamp[account] = block.timestamp;
        }
        require(_dailyMintedAmounts[account] + amount <= _dailyMintCap, "TokenBase: daily mint cap exceeded");
        require(totalSupply() + amount <= _cap, "TokenBase: cap exceeded");
        _mint(account, amount);
        _dailyMintedAmounts[account] += amount;
    }

    function burn(address account, uint256 amount) external onlyOwner { // Added burn method
        _burn(account, amount);
    }

    function setCap(uint256 newCap) external onlyOwner {
        require(newCap > 0, "Cap must be > 0");
        _cap = newCap;
        emit CapSet(newCap);
    }

    function setNewDailyMintCap(uint256 newCap) external onlyOwner {
        require(newCap > 0, "Cap must be > 0");
        _dailyMintCap = newCap;
        emit DailyCapSet(newCap);
    }

    fallback() external {
        revert("TokenBase: invalid function call");
    }
}