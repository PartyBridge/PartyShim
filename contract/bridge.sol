// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TokenBase is ERC20 {
    address private _owner;
    uint256 private _cap;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _owner = msg.sender;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function mint(address account, uint256 amount) external onlyOwner {
        _mint(account, amount);
    }

    function burn(address account, uint256 amount) external onlyOwner {
        _burn(account, amount);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "TokenBase: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "TokenBase: caller is not the owner");
        _;
    }

    fallback() external {
        revert("TokenBase: invalid function call");
    }
}
