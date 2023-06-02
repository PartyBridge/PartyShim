// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package be

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// PartyBridgeMetaData contains all meta data concerning the PartyBridge contract.
var PartyBridgeMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"string\",\"name\":\"name\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"symbol\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"initialCap\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"initialDailyMintCap\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Approval\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"cap\",\"type\":\"uint256\"}],\"name\":\"CapSet\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Transfer\",\"type\":\"event\"},{\"stateMutability\":\"nonpayable\",\"type\":\"fallback\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"}],\"name\":\"allowance\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"approve\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"burn\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"cap\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"dailyMintCap\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"dailyMintedAmount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"decimals\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"subtractedValue\",\"type\":\"uint256\"}],\"name\":\"decreaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"addedValue\",\"type\":\"uint256\"}],\"name\":\"increaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"lastMintTimestamp\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"mint\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"newCap\",\"type\":\"uint256\"}],\"name\":\"setCap\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"symbol\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"totalSupply\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
}

// PartyBridgeABI is the input ABI used to generate the binding from.
// Deprecated: Use PartyBridgeMetaData.ABI instead.
var PartyBridgeABI = PartyBridgeMetaData.ABI

// PartyBridge is an auto generated Go binding around an Ethereum contract.
type PartyBridge struct {
	PartyBridgeCaller     // Read-only binding to the contract
	PartyBridgeTransactor // Write-only binding to the contract
	PartyBridgeFilterer   // Log filterer for contract events
}

// PartyBridgeCaller is an auto generated read-only Go binding around an Ethereum contract.
type PartyBridgeCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PartyBridgeTransactor is an auto generated write-only Go binding around an Ethereum contract.
type PartyBridgeTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PartyBridgeFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type PartyBridgeFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PartyBridgeSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type PartyBridgeSession struct {
	Contract     *PartyBridge      // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// PartyBridgeCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type PartyBridgeCallerSession struct {
	Contract *PartyBridgeCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts      // Call options to use throughout this session
}

// PartyBridgeTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type PartyBridgeTransactorSession struct {
	Contract     *PartyBridgeTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts      // Transaction auth options to use throughout this session
}

// PartyBridgeRaw is an auto generated low-level Go binding around an Ethereum contract.
type PartyBridgeRaw struct {
	Contract *PartyBridge // Generic contract binding to access the raw methods on
}

// PartyBridgeCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type PartyBridgeCallerRaw struct {
	Contract *PartyBridgeCaller // Generic read-only contract binding to access the raw methods on
}

// PartyBridgeTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type PartyBridgeTransactorRaw struct {
	Contract *PartyBridgeTransactor // Generic write-only contract binding to access the raw methods on
}

// NewPartyBridge creates a new instance of PartyBridge, bound to a specific deployed contract.
func NewPartyBridge(address common.Address, backend bind.ContractBackend) (*PartyBridge, error) {
	contract, err := bindPartyBridge(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &PartyBridge{PartyBridgeCaller: PartyBridgeCaller{contract: contract}, PartyBridgeTransactor: PartyBridgeTransactor{contract: contract}, PartyBridgeFilterer: PartyBridgeFilterer{contract: contract}}, nil
}

// NewPartyBridgeCaller creates a new read-only instance of PartyBridge, bound to a specific deployed contract.
func NewPartyBridgeCaller(address common.Address, caller bind.ContractCaller) (*PartyBridgeCaller, error) {
	contract, err := bindPartyBridge(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &PartyBridgeCaller{contract: contract}, nil
}

// NewPartyBridgeTransactor creates a new write-only instance of PartyBridge, bound to a specific deployed contract.
func NewPartyBridgeTransactor(address common.Address, transactor bind.ContractTransactor) (*PartyBridgeTransactor, error) {
	contract, err := bindPartyBridge(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &PartyBridgeTransactor{contract: contract}, nil
}

// NewPartyBridgeFilterer creates a new log filterer instance of PartyBridge, bound to a specific deployed contract.
func NewPartyBridgeFilterer(address common.Address, filterer bind.ContractFilterer) (*PartyBridgeFilterer, error) {
	contract, err := bindPartyBridge(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &PartyBridgeFilterer{contract: contract}, nil
}

// bindPartyBridge binds a generic wrapper to an already deployed contract.
func bindPartyBridge(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := PartyBridgeMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_PartyBridge *PartyBridgeRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _PartyBridge.Contract.PartyBridgeCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_PartyBridge *PartyBridgeRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _PartyBridge.Contract.PartyBridgeTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_PartyBridge *PartyBridgeRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _PartyBridge.Contract.PartyBridgeTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_PartyBridge *PartyBridgeCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _PartyBridge.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_PartyBridge *PartyBridgeTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _PartyBridge.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_PartyBridge *PartyBridgeTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _PartyBridge.Contract.contract.Transact(opts, method, params...)
}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_PartyBridge *PartyBridgeCaller) Allowance(opts *bind.CallOpts, owner common.Address, spender common.Address) (*big.Int, error) {
	var out []interface{}
	err := _PartyBridge.contract.Call(opts, &out, "allowance", owner, spender)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_PartyBridge *PartyBridgeSession) Allowance(owner common.Address, spender common.Address) (*big.Int, error) {
	return _PartyBridge.Contract.Allowance(&_PartyBridge.CallOpts, owner, spender)
}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_PartyBridge *PartyBridgeCallerSession) Allowance(owner common.Address, spender common.Address) (*big.Int, error) {
	return _PartyBridge.Contract.Allowance(&_PartyBridge.CallOpts, owner, spender)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_PartyBridge *PartyBridgeCaller) BalanceOf(opts *bind.CallOpts, account common.Address) (*big.Int, error) {
	var out []interface{}
	err := _PartyBridge.contract.Call(opts, &out, "balanceOf", account)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_PartyBridge *PartyBridgeSession) BalanceOf(account common.Address) (*big.Int, error) {
	return _PartyBridge.Contract.BalanceOf(&_PartyBridge.CallOpts, account)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_PartyBridge *PartyBridgeCallerSession) BalanceOf(account common.Address) (*big.Int, error) {
	return _PartyBridge.Contract.BalanceOf(&_PartyBridge.CallOpts, account)
}

// Cap is a free data retrieval call binding the contract method 0x355274ea.
//
// Solidity: function cap() view returns(uint256)
func (_PartyBridge *PartyBridgeCaller) Cap(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _PartyBridge.contract.Call(opts, &out, "cap")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Cap is a free data retrieval call binding the contract method 0x355274ea.
//
// Solidity: function cap() view returns(uint256)
func (_PartyBridge *PartyBridgeSession) Cap() (*big.Int, error) {
	return _PartyBridge.Contract.Cap(&_PartyBridge.CallOpts)
}

// Cap is a free data retrieval call binding the contract method 0x355274ea.
//
// Solidity: function cap() view returns(uint256)
func (_PartyBridge *PartyBridgeCallerSession) Cap() (*big.Int, error) {
	return _PartyBridge.Contract.Cap(&_PartyBridge.CallOpts)
}

// DailyMintCap is a free data retrieval call binding the contract method 0x2832bcb5.
//
// Solidity: function dailyMintCap() view returns(uint256)
func (_PartyBridge *PartyBridgeCaller) DailyMintCap(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _PartyBridge.contract.Call(opts, &out, "dailyMintCap")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// DailyMintCap is a free data retrieval call binding the contract method 0x2832bcb5.
//
// Solidity: function dailyMintCap() view returns(uint256)
func (_PartyBridge *PartyBridgeSession) DailyMintCap() (*big.Int, error) {
	return _PartyBridge.Contract.DailyMintCap(&_PartyBridge.CallOpts)
}

// DailyMintCap is a free data retrieval call binding the contract method 0x2832bcb5.
//
// Solidity: function dailyMintCap() view returns(uint256)
func (_PartyBridge *PartyBridgeCallerSession) DailyMintCap() (*big.Int, error) {
	return _PartyBridge.Contract.DailyMintCap(&_PartyBridge.CallOpts)
}

// DailyMintedAmount is a free data retrieval call binding the contract method 0x213dd9fa.
//
// Solidity: function dailyMintedAmount(address account) view returns(uint256)
func (_PartyBridge *PartyBridgeCaller) DailyMintedAmount(opts *bind.CallOpts, account common.Address) (*big.Int, error) {
	var out []interface{}
	err := _PartyBridge.contract.Call(opts, &out, "dailyMintedAmount", account)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// DailyMintedAmount is a free data retrieval call binding the contract method 0x213dd9fa.
//
// Solidity: function dailyMintedAmount(address account) view returns(uint256)
func (_PartyBridge *PartyBridgeSession) DailyMintedAmount(account common.Address) (*big.Int, error) {
	return _PartyBridge.Contract.DailyMintedAmount(&_PartyBridge.CallOpts, account)
}

// DailyMintedAmount is a free data retrieval call binding the contract method 0x213dd9fa.
//
// Solidity: function dailyMintedAmount(address account) view returns(uint256)
func (_PartyBridge *PartyBridgeCallerSession) DailyMintedAmount(account common.Address) (*big.Int, error) {
	return _PartyBridge.Contract.DailyMintedAmount(&_PartyBridge.CallOpts, account)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_PartyBridge *PartyBridgeCaller) Decimals(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _PartyBridge.contract.Call(opts, &out, "decimals")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_PartyBridge *PartyBridgeSession) Decimals() (uint8, error) {
	return _PartyBridge.Contract.Decimals(&_PartyBridge.CallOpts)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_PartyBridge *PartyBridgeCallerSession) Decimals() (uint8, error) {
	return _PartyBridge.Contract.Decimals(&_PartyBridge.CallOpts)
}

// LastMintTimestamp is a free data retrieval call binding the contract method 0x8e80ff5d.
//
// Solidity: function lastMintTimestamp() view returns(uint256)
func (_PartyBridge *PartyBridgeCaller) LastMintTimestamp(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _PartyBridge.contract.Call(opts, &out, "lastMintTimestamp")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// LastMintTimestamp is a free data retrieval call binding the contract method 0x8e80ff5d.
//
// Solidity: function lastMintTimestamp() view returns(uint256)
func (_PartyBridge *PartyBridgeSession) LastMintTimestamp() (*big.Int, error) {
	return _PartyBridge.Contract.LastMintTimestamp(&_PartyBridge.CallOpts)
}

// LastMintTimestamp is a free data retrieval call binding the contract method 0x8e80ff5d.
//
// Solidity: function lastMintTimestamp() view returns(uint256)
func (_PartyBridge *PartyBridgeCallerSession) LastMintTimestamp() (*big.Int, error) {
	return _PartyBridge.Contract.LastMintTimestamp(&_PartyBridge.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_PartyBridge *PartyBridgeCaller) Name(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _PartyBridge.contract.Call(opts, &out, "name")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_PartyBridge *PartyBridgeSession) Name() (string, error) {
	return _PartyBridge.Contract.Name(&_PartyBridge.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_PartyBridge *PartyBridgeCallerSession) Name() (string, error) {
	return _PartyBridge.Contract.Name(&_PartyBridge.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_PartyBridge *PartyBridgeCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _PartyBridge.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_PartyBridge *PartyBridgeSession) Owner() (common.Address, error) {
	return _PartyBridge.Contract.Owner(&_PartyBridge.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_PartyBridge *PartyBridgeCallerSession) Owner() (common.Address, error) {
	return _PartyBridge.Contract.Owner(&_PartyBridge.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_PartyBridge *PartyBridgeCaller) Symbol(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _PartyBridge.contract.Call(opts, &out, "symbol")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_PartyBridge *PartyBridgeSession) Symbol() (string, error) {
	return _PartyBridge.Contract.Symbol(&_PartyBridge.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_PartyBridge *PartyBridgeCallerSession) Symbol() (string, error) {
	return _PartyBridge.Contract.Symbol(&_PartyBridge.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_PartyBridge *PartyBridgeCaller) TotalSupply(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _PartyBridge.contract.Call(opts, &out, "totalSupply")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_PartyBridge *PartyBridgeSession) TotalSupply() (*big.Int, error) {
	return _PartyBridge.Contract.TotalSupply(&_PartyBridge.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_PartyBridge *PartyBridgeCallerSession) TotalSupply() (*big.Int, error) {
	return _PartyBridge.Contract.TotalSupply(&_PartyBridge.CallOpts)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 amount) returns(bool)
func (_PartyBridge *PartyBridgeTransactor) Approve(opts *bind.TransactOpts, spender common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.contract.Transact(opts, "approve", spender, amount)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 amount) returns(bool)
func (_PartyBridge *PartyBridgeSession) Approve(spender common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.Approve(&_PartyBridge.TransactOpts, spender, amount)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 amount) returns(bool)
func (_PartyBridge *PartyBridgeTransactorSession) Approve(spender common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.Approve(&_PartyBridge.TransactOpts, spender, amount)
}

// Burn is a paid mutator transaction binding the contract method 0x9dc29fac.
//
// Solidity: function burn(address account, uint256 amount) returns()
func (_PartyBridge *PartyBridgeTransactor) Burn(opts *bind.TransactOpts, account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.contract.Transact(opts, "burn", account, amount)
}

// Burn is a paid mutator transaction binding the contract method 0x9dc29fac.
//
// Solidity: function burn(address account, uint256 amount) returns()
func (_PartyBridge *PartyBridgeSession) Burn(account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.Burn(&_PartyBridge.TransactOpts, account, amount)
}

// Burn is a paid mutator transaction binding the contract method 0x9dc29fac.
//
// Solidity: function burn(address account, uint256 amount) returns()
func (_PartyBridge *PartyBridgeTransactorSession) Burn(account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.Burn(&_PartyBridge.TransactOpts, account, amount)
}

// DecreaseAllowance is a paid mutator transaction binding the contract method 0xa457c2d7.
//
// Solidity: function decreaseAllowance(address spender, uint256 subtractedValue) returns(bool)
func (_PartyBridge *PartyBridgeTransactor) DecreaseAllowance(opts *bind.TransactOpts, spender common.Address, subtractedValue *big.Int) (*types.Transaction, error) {
	return _PartyBridge.contract.Transact(opts, "decreaseAllowance", spender, subtractedValue)
}

// DecreaseAllowance is a paid mutator transaction binding the contract method 0xa457c2d7.
//
// Solidity: function decreaseAllowance(address spender, uint256 subtractedValue) returns(bool)
func (_PartyBridge *PartyBridgeSession) DecreaseAllowance(spender common.Address, subtractedValue *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.DecreaseAllowance(&_PartyBridge.TransactOpts, spender, subtractedValue)
}

// DecreaseAllowance is a paid mutator transaction binding the contract method 0xa457c2d7.
//
// Solidity: function decreaseAllowance(address spender, uint256 subtractedValue) returns(bool)
func (_PartyBridge *PartyBridgeTransactorSession) DecreaseAllowance(spender common.Address, subtractedValue *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.DecreaseAllowance(&_PartyBridge.TransactOpts, spender, subtractedValue)
}

// IncreaseAllowance is a paid mutator transaction binding the contract method 0x39509351.
//
// Solidity: function increaseAllowance(address spender, uint256 addedValue) returns(bool)
func (_PartyBridge *PartyBridgeTransactor) IncreaseAllowance(opts *bind.TransactOpts, spender common.Address, addedValue *big.Int) (*types.Transaction, error) {
	return _PartyBridge.contract.Transact(opts, "increaseAllowance", spender, addedValue)
}

// IncreaseAllowance is a paid mutator transaction binding the contract method 0x39509351.
//
// Solidity: function increaseAllowance(address spender, uint256 addedValue) returns(bool)
func (_PartyBridge *PartyBridgeSession) IncreaseAllowance(spender common.Address, addedValue *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.IncreaseAllowance(&_PartyBridge.TransactOpts, spender, addedValue)
}

// IncreaseAllowance is a paid mutator transaction binding the contract method 0x39509351.
//
// Solidity: function increaseAllowance(address spender, uint256 addedValue) returns(bool)
func (_PartyBridge *PartyBridgeTransactorSession) IncreaseAllowance(spender common.Address, addedValue *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.IncreaseAllowance(&_PartyBridge.TransactOpts, spender, addedValue)
}

// Mint is a paid mutator transaction binding the contract method 0x40c10f19.
//
// Solidity: function mint(address account, uint256 amount) returns()
func (_PartyBridge *PartyBridgeTransactor) Mint(opts *bind.TransactOpts, account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.contract.Transact(opts, "mint", account, amount)
}

// Mint is a paid mutator transaction binding the contract method 0x40c10f19.
//
// Solidity: function mint(address account, uint256 amount) returns()
func (_PartyBridge *PartyBridgeSession) Mint(account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.Mint(&_PartyBridge.TransactOpts, account, amount)
}

// Mint is a paid mutator transaction binding the contract method 0x40c10f19.
//
// Solidity: function mint(address account, uint256 amount) returns()
func (_PartyBridge *PartyBridgeTransactorSession) Mint(account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.Mint(&_PartyBridge.TransactOpts, account, amount)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_PartyBridge *PartyBridgeTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _PartyBridge.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_PartyBridge *PartyBridgeSession) RenounceOwnership() (*types.Transaction, error) {
	return _PartyBridge.Contract.RenounceOwnership(&_PartyBridge.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_PartyBridge *PartyBridgeTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _PartyBridge.Contract.RenounceOwnership(&_PartyBridge.TransactOpts)
}

// SetCap is a paid mutator transaction binding the contract method 0x47786d37.
//
// Solidity: function setCap(uint256 newCap) returns()
func (_PartyBridge *PartyBridgeTransactor) SetCap(opts *bind.TransactOpts, newCap *big.Int) (*types.Transaction, error) {
	return _PartyBridge.contract.Transact(opts, "setCap", newCap)
}

// SetCap is a paid mutator transaction binding the contract method 0x47786d37.
//
// Solidity: function setCap(uint256 newCap) returns()
func (_PartyBridge *PartyBridgeSession) SetCap(newCap *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.SetCap(&_PartyBridge.TransactOpts, newCap)
}

// SetCap is a paid mutator transaction binding the contract method 0x47786d37.
//
// Solidity: function setCap(uint256 newCap) returns()
func (_PartyBridge *PartyBridgeTransactorSession) SetCap(newCap *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.SetCap(&_PartyBridge.TransactOpts, newCap)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address to, uint256 amount) returns(bool)
func (_PartyBridge *PartyBridgeTransactor) Transfer(opts *bind.TransactOpts, to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.contract.Transact(opts, "transfer", to, amount)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address to, uint256 amount) returns(bool)
func (_PartyBridge *PartyBridgeSession) Transfer(to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.Transfer(&_PartyBridge.TransactOpts, to, amount)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address to, uint256 amount) returns(bool)
func (_PartyBridge *PartyBridgeTransactorSession) Transfer(to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.Transfer(&_PartyBridge.TransactOpts, to, amount)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 amount) returns(bool)
func (_PartyBridge *PartyBridgeTransactor) TransferFrom(opts *bind.TransactOpts, from common.Address, to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.contract.Transact(opts, "transferFrom", from, to, amount)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 amount) returns(bool)
func (_PartyBridge *PartyBridgeSession) TransferFrom(from common.Address, to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.TransferFrom(&_PartyBridge.TransactOpts, from, to, amount)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 amount) returns(bool)
func (_PartyBridge *PartyBridgeTransactorSession) TransferFrom(from common.Address, to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _PartyBridge.Contract.TransferFrom(&_PartyBridge.TransactOpts, from, to, amount)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_PartyBridge *PartyBridgeTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _PartyBridge.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_PartyBridge *PartyBridgeSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _PartyBridge.Contract.TransferOwnership(&_PartyBridge.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_PartyBridge *PartyBridgeTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _PartyBridge.Contract.TransferOwnership(&_PartyBridge.TransactOpts, newOwner)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() returns()
func (_PartyBridge *PartyBridgeTransactor) Fallback(opts *bind.TransactOpts, calldata []byte) (*types.Transaction, error) {
	return _PartyBridge.contract.RawTransact(opts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() returns()
func (_PartyBridge *PartyBridgeSession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _PartyBridge.Contract.Fallback(&_PartyBridge.TransactOpts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() returns()
func (_PartyBridge *PartyBridgeTransactorSession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _PartyBridge.Contract.Fallback(&_PartyBridge.TransactOpts, calldata)
}

// PartyBridgeApprovalIterator is returned from FilterApproval and is used to iterate over the raw logs and unpacked data for Approval events raised by the PartyBridge contract.
type PartyBridgeApprovalIterator struct {
	Event *PartyBridgeApproval // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *PartyBridgeApprovalIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(PartyBridgeApproval)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(PartyBridgeApproval)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *PartyBridgeApprovalIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *PartyBridgeApprovalIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// PartyBridgeApproval represents a Approval event raised by the PartyBridge contract.
type PartyBridgeApproval struct {
	Owner   common.Address
	Spender common.Address
	Value   *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterApproval is a free log retrieval operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed spender, uint256 value)
func (_PartyBridge *PartyBridgeFilterer) FilterApproval(opts *bind.FilterOpts, owner []common.Address, spender []common.Address) (*PartyBridgeApprovalIterator, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var spenderRule []interface{}
	for _, spenderItem := range spender {
		spenderRule = append(spenderRule, spenderItem)
	}

	logs, sub, err := _PartyBridge.contract.FilterLogs(opts, "Approval", ownerRule, spenderRule)
	if err != nil {
		return nil, err
	}
	return &PartyBridgeApprovalIterator{contract: _PartyBridge.contract, event: "Approval", logs: logs, sub: sub}, nil
}

// WatchApproval is a free log subscription operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed spender, uint256 value)
func (_PartyBridge *PartyBridgeFilterer) WatchApproval(opts *bind.WatchOpts, sink chan<- *PartyBridgeApproval, owner []common.Address, spender []common.Address) (event.Subscription, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var spenderRule []interface{}
	for _, spenderItem := range spender {
		spenderRule = append(spenderRule, spenderItem)
	}

	logs, sub, err := _PartyBridge.contract.WatchLogs(opts, "Approval", ownerRule, spenderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(PartyBridgeApproval)
				if err := _PartyBridge.contract.UnpackLog(event, "Approval", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseApproval is a log parse operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed spender, uint256 value)
func (_PartyBridge *PartyBridgeFilterer) ParseApproval(log types.Log) (*PartyBridgeApproval, error) {
	event := new(PartyBridgeApproval)
	if err := _PartyBridge.contract.UnpackLog(event, "Approval", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// PartyBridgeCapSetIterator is returned from FilterCapSet and is used to iterate over the raw logs and unpacked data for CapSet events raised by the PartyBridge contract.
type PartyBridgeCapSetIterator struct {
	Event *PartyBridgeCapSet // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *PartyBridgeCapSetIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(PartyBridgeCapSet)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(PartyBridgeCapSet)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *PartyBridgeCapSetIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *PartyBridgeCapSetIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// PartyBridgeCapSet represents a CapSet event raised by the PartyBridge contract.
type PartyBridgeCapSet struct {
	Cap *big.Int
	Raw types.Log // Blockchain specific contextual infos
}

// FilterCapSet is a free log retrieval operation binding the contract event 0x9872d5eb566b79923d043f1b59aca655ca80a2bb5b6bca4824e515b0e398902f.
//
// Solidity: event CapSet(uint256 cap)
func (_PartyBridge *PartyBridgeFilterer) FilterCapSet(opts *bind.FilterOpts) (*PartyBridgeCapSetIterator, error) {

	logs, sub, err := _PartyBridge.contract.FilterLogs(opts, "CapSet")
	if err != nil {
		return nil, err
	}
	return &PartyBridgeCapSetIterator{contract: _PartyBridge.contract, event: "CapSet", logs: logs, sub: sub}, nil
}

// WatchCapSet is a free log subscription operation binding the contract event 0x9872d5eb566b79923d043f1b59aca655ca80a2bb5b6bca4824e515b0e398902f.
//
// Solidity: event CapSet(uint256 cap)
func (_PartyBridge *PartyBridgeFilterer) WatchCapSet(opts *bind.WatchOpts, sink chan<- *PartyBridgeCapSet) (event.Subscription, error) {

	logs, sub, err := _PartyBridge.contract.WatchLogs(opts, "CapSet")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(PartyBridgeCapSet)
				if err := _PartyBridge.contract.UnpackLog(event, "CapSet", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseCapSet is a log parse operation binding the contract event 0x9872d5eb566b79923d043f1b59aca655ca80a2bb5b6bca4824e515b0e398902f.
//
// Solidity: event CapSet(uint256 cap)
func (_PartyBridge *PartyBridgeFilterer) ParseCapSet(log types.Log) (*PartyBridgeCapSet, error) {
	event := new(PartyBridgeCapSet)
	if err := _PartyBridge.contract.UnpackLog(event, "CapSet", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// PartyBridgeOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the PartyBridge contract.
type PartyBridgeOwnershipTransferredIterator struct {
	Event *PartyBridgeOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *PartyBridgeOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(PartyBridgeOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(PartyBridgeOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *PartyBridgeOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *PartyBridgeOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// PartyBridgeOwnershipTransferred represents a OwnershipTransferred event raised by the PartyBridge contract.
type PartyBridgeOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_PartyBridge *PartyBridgeFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*PartyBridgeOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _PartyBridge.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &PartyBridgeOwnershipTransferredIterator{contract: _PartyBridge.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_PartyBridge *PartyBridgeFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *PartyBridgeOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _PartyBridge.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(PartyBridgeOwnershipTransferred)
				if err := _PartyBridge.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_PartyBridge *PartyBridgeFilterer) ParseOwnershipTransferred(log types.Log) (*PartyBridgeOwnershipTransferred, error) {
	event := new(PartyBridgeOwnershipTransferred)
	if err := _PartyBridge.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// PartyBridgeTransferIterator is returned from FilterTransfer and is used to iterate over the raw logs and unpacked data for Transfer events raised by the PartyBridge contract.
type PartyBridgeTransferIterator struct {
	Event *PartyBridgeTransfer // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *PartyBridgeTransferIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(PartyBridgeTransfer)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(PartyBridgeTransfer)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *PartyBridgeTransferIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *PartyBridgeTransferIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// PartyBridgeTransfer represents a Transfer event raised by the PartyBridge contract.
type PartyBridgeTransfer struct {
	From  common.Address
	To    common.Address
	Value *big.Int
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterTransfer is a free log retrieval operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 value)
func (_PartyBridge *PartyBridgeFilterer) FilterTransfer(opts *bind.FilterOpts, from []common.Address, to []common.Address) (*PartyBridgeTransferIterator, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	logs, sub, err := _PartyBridge.contract.FilterLogs(opts, "Transfer", fromRule, toRule)
	if err != nil {
		return nil, err
	}
	return &PartyBridgeTransferIterator{contract: _PartyBridge.contract, event: "Transfer", logs: logs, sub: sub}, nil
}

// WatchTransfer is a free log subscription operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 value)
func (_PartyBridge *PartyBridgeFilterer) WatchTransfer(opts *bind.WatchOpts, sink chan<- *PartyBridgeTransfer, from []common.Address, to []common.Address) (event.Subscription, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	logs, sub, err := _PartyBridge.contract.WatchLogs(opts, "Transfer", fromRule, toRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(PartyBridgeTransfer)
				if err := _PartyBridge.contract.UnpackLog(event, "Transfer", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseTransfer is a log parse operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 value)
func (_PartyBridge *PartyBridgeFilterer) ParseTransfer(log types.Log) (*PartyBridgeTransfer, error) {
	event := new(PartyBridgeTransfer)
	if err := _PartyBridge.contract.UnpackLog(event, "Transfer", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
