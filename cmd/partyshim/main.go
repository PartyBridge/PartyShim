package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/event"

	bridge "github.com/TeaPartyCrypto/PartyShim/contract/v2"
)

type MintRequest struct {
	ToAddress string   `json:"toAddress"`
	Amount    *big.Int `json:"amount"`
	FromPK    string   `json:"fromPK"`
}

type PartyShim struct {
	// the private key of the contract owner
	privateKey            *ecdsa.PrivateKey
	defaultPaymentKey     *ecdsa.PrivateKey
	RPCURL                string
	RPCURL2               string
	ContractAddress       string
	BSCGasPayerPrivateKey string
}

func main() {
	// import the private key from the environment variable
	privateKey := os.Getenv("PRIVATE_KEY")
	if privateKey == "" {
		panic("PRIVATE_KEY environment variable not set")
	}
	defaultPaymentPK := os.Getenv("DEFAULT_PAYMENT_PRIVATE_KEY")
	if defaultPaymentPK == "" {
		panic("DEFAULT_PAYMENT_PRIVATE_KEY environment variable not set")
	}
	RPCURL := os.Getenv("RPC_URL")
	if RPCURL == "" {
		panic("RPC_URL environment variable not set")
	}
	RPCURL2 := os.Getenv("RPC_URL2")
	if RPCURL2 == "" {
		panic("RPC_URL2 environment variable not set")
	}
	ContractAddress := os.Getenv("CONTRACT_ADDRESS")
	if ContractAddress == "" {
		panic("CONTRACT_ADDRESS environment variable not set")
	}
	CACertLocation := os.Getenv("SHIM_CA_CERT")
	if CACertLocation == "" {
		panic("SHIM_CA_CERT environment variable not set")
	}

	BSCGasPayerPrivateKey := os.Getenv("BSC_GAS_PAYER_PRIVATE_KEY")
	if BSCGasPayerPrivateKey == "" {
		panic("BSC_GAS_PAYER_PRIVATE_KEY environment variable not set")
	}

	// create a new ecdsa private key from the plain text private key
	pkECDSA, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		fmt.Println(err)
	}

	// create a new ecdsa private key from the plain text private key
	defaultPaymentPKECDSA, err := crypto.HexToECDSA(defaultPaymentPK)
	if err != nil {
		fmt.Println(err)
	}

	ps := &PartyShim{
		privateKey:            pkECDSA,
		defaultPaymentKey:     defaultPaymentPKECDSA,
		RPCURL:                RPCURL,
		RPCURL2:               RPCURL2,
		ContractAddress:       ContractAddress,
		BSCGasPayerPrivateKey: BSCGasPayerPrivateKey,
	}
	// Read the certificate and private key files
	cert, err := tls.LoadX509KeyPair(CACertLocation+"/server.crt", CACertLocation+"/server.key")
	if err != nil {
		log.Fatalf("failed to load certificate and private key: %v", err)
	}

	// Load the CA certificate used to sign the client certificates.
	caCert, err := ioutil.ReadFile(CACertLocation + "/ca.crt")
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Configure TLS options.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs: caCertPool,
	}

	handler := http.NewServeMux()
	handler.HandleFunc("/mint", ps.mint)
	handler.HandleFunc("/transfer", ps.transfer)
	handler.HandleFunc("/transferBSCUSDT", ps.transferBUSDT)

	// Create a server with the TLS configuration
	server := &http.Server{
		Addr:      ":8080",
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	fmt.Println("Starting shim on port 8080")
	// Start the HTTPS server with TLS
	log.Fatal(server.ListenAndServeTLS("", ""))
}

// mint exposes an interface to mint the wrapped currency
func (e *PartyShim) mint(w http.ResponseWriter, r *http.Request) {
	mintRequest := &MintRequest{}
	// decode the request body into the MintRequest struct
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(mintRequest)
	if err != nil {
		fmt.Println(err)
	}

	// Contract owners, feel free to add additional logic here
	// to farther validate the transaction before signing it
	// Just notify me if you do.

	// mint the transaction
	err, txid := e.completeMint(*mintRequest)
	if err != nil {
		fmt.Println(err)
		w.Write([]byte(err.Error()))
		return
	}

	// return the signed transaction
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(txid)
}

// completeMint will complete the minting of the wrapped currency
func (e *PartyShim) completeMint(mr MintRequest) (error, string) {
	ctx := context.Background()
	// initialize the Party Chain nodes.
	partyclient, err := ethclient.Dial(e.RPCURL)
	if err != nil {
		return err, ""
	}

	publicKey := e.privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return err, ""
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := partyclient.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return err, ""
	}

	gasPrice, err := partyclient.SuggestGasPrice(ctx)
	if err != nil {
		return err, ""
	}

	// set chain id
	chainID, err := partyclient.ChainID(ctx)
	if err != nil {
		return err, ""
	}

	auth, err := bind.NewKeyedTransactorWithChainID(e.privateKey, chainID)
	if err != nil {
		return err, ""
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)      // in wei
	auth.GasLimit = uint64(3000000) // in units
	auth.GasPrice = gasPrice
	auth.From = fromAddress

	contractaddress := common.HexToAddress(e.ContractAddress)
	instance, err := bridge.NewPartyBridge(contractaddress, partyclient)
	if err != nil {
		return err, ""
	}

	toadr := common.HexToAddress(mr.ToAddress)

	// Call the mint function on the contract
	tx, err := instance.Mint(auth, toadr, mr.Amount)
	if err != nil {
		return err, ""
	}

	fmt.Printf("tx sent: %s \n", tx.Hash().Hex())

	// wait for the transaction to be mined
	for pending := true; pending; _, pending, err = partyclient.TransactionByHash(ctx, tx.Hash()) {
		if err != nil {
			return err, ""
		}
		time.Sleep(2 * time.Second)
	}

	fmt.Println("tx mined")

	return nil, tx.Hash().Hex()
}

func (e *PartyShim) transfer(w http.ResponseWriter, r *http.Request) {
	transferRequest := &MintRequest{}
	// decode the request body into the MintRequest struct
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(transferRequest)
	if err != nil {
		fmt.Println(err)
	}

	// Contract owners, feel free to add additional logic here
	// to farther validate the transaction before signing it
	// Just notify me if you do.

	var pk *ecdsa.PrivateKey
	if transferRequest.FromPK != "" {
		// convert the privateKey string to ecdsa.PrivateKey
		pkECDSA, err := crypto.HexToECDSA(transferRequest.FromPK)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}
		pk = pkECDSA
	} else {
		pk = e.defaultPaymentKey
	}

	// Complete the transfer
	err, txid := e.completeTransfer(*transferRequest, pk)
	if err != nil {
		fmt.Println(err)
		w.Write([]byte("insufficient balance"))
	}

	// return the transaction id
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(txid)
}

// burn will remove the minted wrapped tokens from circulation
func (e *PartyShim) burn(mr MintRequest) error {
	ctx := context.Background()
	// initialize the Party Chain nodes.
	partyclient, err := ethclient.Dial(e.RPCURL)
	if err != nil {
		log.Fatal(err)
	}

	publicKey := e.privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := partyclient.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	gasPrice, err := partyclient.SuggestGasPrice(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// set chain id
	chainID, err := partyclient.ChainID(ctx)
	if err != nil {
		log.Fatal(err)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(e.privateKey, chainID)
	if err != nil {
		log.Fatal(err)
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)      // in wei
	auth.GasLimit = uint64(3000000) // in units
	auth.GasPrice = gasPrice
	auth.From = fromAddress

	// initialize the contract
	contract, err := bridge.NewPartyBridge(common.HexToAddress(e.ContractAddress), partyclient)
	if err != nil {
		log.Fatal(err)
	}

	// burn the tokens
	tx, err := contract.Burn(auth, common.HexToAddress(mr.ToAddress), mr.Amount)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("burn tx sent: %s", tx.Hash().Hex())

	return nil
}

func (e *PartyShim) completeTransfer(mr MintRequest, privateKey *ecdsa.PrivateKey) (error, *string) {
	ctx := context.Background()
	// initialize the Party Chain nodes.
	partyclient, err := ethclient.Dial(e.RPCURL2)
	if err != nil {
		return err, nil
	}

	// check the connection status of the ethclient
	i, err := partyclient.PeerCount(ctx)
	if err != nil {
		return err, nil
	}

	fmt.Println("Party Chain Peer Count: ", i)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey"), nil
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := partyclient.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return err, nil
	}

	gasPrice, err := partyclient.SuggestGasPrice(context.Background())
	if err != nil {
		return err, nil
	}
	gasLimit := uint64(29000) // Increased gasLimit from 21000 to 29000 in case of token transfers.

	// Fetch account balance
	balance, err := partyclient.BalanceAt(ctx, fromAddress, nil)
	if err != nil {
		return err, nil
	}

	// Calculate total cost
	totalCost := new(big.Int)
	totalCost = totalCost.Mul(gasPrice, big.NewInt(int64(gasLimit))) // totalCost = gasPrice * gasLimit
	totalCost = totalCost.Add(totalCost, mr.Amount)                  // totalCost = totalCost + Amount

	// If balance is less than total cost, adjust the transfer value
	if balance.Cmp(totalCost) == -1 {
		mr.Amount = new(big.Int).Sub(balance, new(big.Int).Mul(gasPrice, big.NewInt(int64(gasLimit))))
	}

	// if the balance is less than 0 after adjustment, return an error
	if mr.Amount.Cmp(big.NewInt(0)) == -1 {
		return errors.New("insufficient balance"), nil
	}

	// set chain id
	chainID, err := partyclient.ChainID(ctx)
	if err != nil {
		return err, nil
	}
	toAddress := common.HexToAddress(mr.ToAddress)
	var data []byte
	tx := types.NewTransaction(nonce, toAddress, mr.Amount, gasLimit, gasPrice, data)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		// if the transaction fails due to insufficient funds, deduct %5 from the amount and try again
		if strings.Contains(err.Error(), "insufficient funds for gas * price + value") {
			mr.Amount = new(big.Int).Sub(mr.Amount, new(big.Int).Mul(mr.Amount, big.NewInt(5)))
			return e.completeTransfer(mr, privateKey)
		}
	}

	if err := partyclient.SendTransaction(ctx, signedTx); err != nil {
		return err, nil
	}

	fmt.Printf("transfer tx sent: %s on chain id: %s to address: %s from address: %s", signedTx.Hash().Hex(), chainID.String(), toAddress.String(), fromAddress.String())
	transactionID := signedTx.Hash().Hex()

	// wait for the transaction to be mined
	for pending := true; pending; _, pending, err = partyclient.TransactionByHash(ctx, signedTx.Hash()) {
		if err != nil {
			return err, nil
		}
		time.Sleep(2 * time.Second)
	}

	fmt.Println("transfer tx mined")

	// burn the minted tokens
	err = e.burn(mr)
	if err != nil {
		return err, nil
	}

	return nil, &transactionID
}

// transferBUSDT transfer BUSDT tokens on the BSC chain
func (e *PartyShim) transferBUSDT(w http.ResponseWriter, r *http.Request) {
	transferRequest := &MintRequest{}
	// decode the request body into the MintRequest struct
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(transferRequest)
	if err != nil {
		fmt.Println(err)
	}

	// Contract owners, feel free to add additional logic here
	// to farther validate the transaction before signing it
	// Just notify me if you do.

	var pk *ecdsa.PrivateKey
	if transferRequest.FromPK != "" {
		// convert the privateKey string to ecdsa.PrivateKey
		pkECDSA, err := crypto.HexToECDSA(transferRequest.FromPK)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}
		pk = pkECDSA
	} else {
		pk = e.defaultPaymentKey
	}

	// fund the account with BNB in order to pay for the transaction fees
	err = e.fundAccount(*transferRequest, pk)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	// Complete the transfer
	err, txid := e.completeBUSDTTransfer(*transferRequest, pk)
	if err != nil {
		fmt.Println(err)
		w.Write([]byte(err.Error()))
	}

	// return the transaction id
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(txid)
}

// complete BUSDT transfer
func (e *PartyShim) completeBUSDTTransfer(mr MintRequest, privateKey *ecdsa.PrivateKey) (error, *string) {
	ctx := context.Background()
	// initialize the bsc client
	bscclient, err := ethclient.Dial(e.RPCURL2)
	if err != nil {
		return err, nil
	}

	// check the connection status of the ethclient
	i, err := bscclient.PeerCount(ctx)
	if err != nil {
		return err, nil
	}

	fmt.Println("BSC Peer Count: ", i)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey"), nil
	}

	// send the BUSDT tokens (0x55d398326f99059fF775485246999027B3197955) to the user
	// from the contract address (0x55d398326f99059fF775485246999027B3197955)
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Printf("from address: %s", fromAddress.String())

	nonce, err := bscclient.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return err, nil
	}

	toAddress := common.HexToAddress(mr.ToAddress)
	fmt.Printf("to address: %s", toAddress.String())
	gasPrice, err := bscclient.SuggestGasPrice(ctx)
	if err != nil {
		return err, nil
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(56))
	if err != nil {
		return err, nil
	}

	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)     // in wei
	auth.GasLimit = uint64(300000) // in units
	auth.GasPrice = gasPrice
	auth.From = fromAddress

	// initialize the BUSDT contract
	address := common.HexToAddress("0x55d398326f99059fF775485246999027B3197955")
	instance, err := NewBscUsdt(address, bscclient)
	if err != nil {
		return err, nil
	}

	fmt.Printf("sending from acount: %s", auth.From.String())

	// call the transfer function
	tx, err := instance.Transfer(auth, toAddress, mr.Amount)
	if err != nil {
		return err, nil
	}

	fmt.Printf("transfer tx sent: %s", tx.Hash().Hex())
	transactionID := tx.Hash().Hex()

	// wait for the transaction to be mined
	for pending := true; pending; _, pending, err = bscclient.TransactionByHash(ctx, tx.Hash()) {
		if err != nil {
			return err, nil
		}
		time.Sleep(2 * time.Second)
	}

	fmt.Println("transfer tx mined")

	// burn the minted tokens
	err = e.burn(mr)
	if err != nil {
		return err, nil
	}

	return nil, &transactionID
}

// fundEscrowAccount transfer BNB to the escrow account in order to send the BUSDT tokens to the user
func (e *PartyShim) fundAccount(mr MintRequest, pk *ecdsa.PrivateKey) error {
	ctx := context.Background()
	// initialize the bsc client
	bscclient, err := ethclient.Dial(e.RPCURL2)
	if err != nil {
		return err
	}

	// check the connection status of the ethclient
	i, err := bscclient.PeerCount(ctx)
	if err != nil {
		return err
	}

	fmt.Println("BSC Peer Count: ", i)

	// convert the privateKey string to ecdsa.PrivateKey
	payersPK, err := crypto.HexToECDSA(e.BSCGasPayerPrivateKey)
	if err != nil {
		return err
	}

	payersPublicKey := payersPK.Public()
	publicKeyECDSA, ok := payersPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	// send the BNB to the escrow account, only enough to pay for the transaction fees
	PayersAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := bscclient.PendingNonceAt(ctx, PayersAddress)
	if err != nil {
		return err
	}

	gasPrice, err := bscclient.SuggestGasPrice(ctx)
	if err != nil {
		return err
	}

	gasLimit := uint64(29000)

	// send .000172 BNB to the escrow account
	value := big.NewInt(1920000000000000)
	chainID := big.NewInt(56)

	toAddressPublicKey := pk.Public()
	toAddressPublicKeyECDSA, ok := toAddressPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	toAddress := crypto.PubkeyToAddress(*toAddressPublicKeyECDSA)
	fmt.Println("sending funds to ", toAddress)

	var data []byte
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), payersPK)
	if err != nil {
		return err
	}

	err = bscclient.SendTransaction(ctx, signedTx)
	if err != nil {
		return err
	}

	fmt.Printf("Tx sent: %s", signedTx.Hash().Hex())

	// wait for the transaction to be mined
	for pending := true; pending; _, pending, err = bscclient.TransactionByHash(ctx, signedTx.Hash()) {
		if err != nil {
			return err
		}
		time.Sleep(2 * time.Second)
	}

	fmt.Println("Tx mined")
	return nil
}

/// codegen

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

// BscUsdtMetaData contains all meta data concerning the BscUsdt contract.
var BscUsdtMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Approval\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Transfer\",\"type\":\"event\"},{\"constant\":true,\"inputs\":[],\"name\":\"_decimals\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"_name\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"_symbol\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"}],\"name\":\"allowance\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"approve\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"balanceOf\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"burn\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"decimals\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"subtractedValue\",\"type\":\"uint256\"}],\"name\":\"decreaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getOwner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"spender\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"addedValue\",\"type\":\"uint256\"}],\"name\":\"increaseAllowance\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"mint\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"symbol\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"totalSupply\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transfer\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"transferFrom\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
}

// BscUsdtABI is the input ABI used to generate the binding from.
// Deprecated: Use BscUsdtMetaData.ABI instead.
var BscUsdtABI = BscUsdtMetaData.ABI

// BscUsdt is an auto generated Go binding around an Ethereum contract.
type BscUsdt struct {
	BscUsdtCaller     // Read-only binding to the contract
	BscUsdtTransactor // Write-only binding to the contract
	BscUsdtFilterer   // Log filterer for contract events
}

// BscUsdtCaller is an auto generated read-only Go binding around an Ethereum contract.
type BscUsdtCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// BscUsdtTransactor is an auto generated write-only Go binding around an Ethereum contract.
type BscUsdtTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// BscUsdtFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type BscUsdtFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// BscUsdtSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type BscUsdtSession struct {
	Contract     *BscUsdt          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// BscUsdtCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type BscUsdtCallerSession struct {
	Contract *BscUsdtCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// BscUsdtTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type BscUsdtTransactorSession struct {
	Contract     *BscUsdtTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// BscUsdtRaw is an auto generated low-level Go binding around an Ethereum contract.
type BscUsdtRaw struct {
	Contract *BscUsdt // Generic contract binding to access the raw methods on
}

// BscUsdtCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type BscUsdtCallerRaw struct {
	Contract *BscUsdtCaller // Generic read-only contract binding to access the raw methods on
}

// BscUsdtTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type BscUsdtTransactorRaw struct {
	Contract *BscUsdtTransactor // Generic write-only contract binding to access the raw methods on
}

// NewBscUsdt creates a new instance of BscUsdt, bound to a specific deployed contract.
func NewBscUsdt(address common.Address, backend bind.ContractBackend) (*BscUsdt, error) {
	contract, err := bindBscUsdt(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &BscUsdt{BscUsdtCaller: BscUsdtCaller{contract: contract}, BscUsdtTransactor: BscUsdtTransactor{contract: contract}, BscUsdtFilterer: BscUsdtFilterer{contract: contract}}, nil
}

// NewBscUsdtCaller creates a new read-only instance of BscUsdt, bound to a specific deployed contract.
func NewBscUsdtCaller(address common.Address, caller bind.ContractCaller) (*BscUsdtCaller, error) {
	contract, err := bindBscUsdt(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &BscUsdtCaller{contract: contract}, nil
}

// NewBscUsdtTransactor creates a new write-only instance of BscUsdt, bound to a specific deployed contract.
func NewBscUsdtTransactor(address common.Address, transactor bind.ContractTransactor) (*BscUsdtTransactor, error) {
	contract, err := bindBscUsdt(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &BscUsdtTransactor{contract: contract}, nil
}

// NewBscUsdtFilterer creates a new log filterer instance of BscUsdt, bound to a specific deployed contract.
func NewBscUsdtFilterer(address common.Address, filterer bind.ContractFilterer) (*BscUsdtFilterer, error) {
	contract, err := bindBscUsdt(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &BscUsdtFilterer{contract: contract}, nil
}

// bindBscUsdt binds a generic wrapper to an already deployed contract.
func bindBscUsdt(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := BscUsdtMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_BscUsdt *BscUsdtRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _BscUsdt.Contract.BscUsdtCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_BscUsdt *BscUsdtRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _BscUsdt.Contract.BscUsdtTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_BscUsdt *BscUsdtRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _BscUsdt.Contract.BscUsdtTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_BscUsdt *BscUsdtCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _BscUsdt.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_BscUsdt *BscUsdtTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _BscUsdt.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_BscUsdt *BscUsdtTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _BscUsdt.Contract.contract.Transact(opts, method, params...)
}

// PrivateDecimals is a free data retrieval call binding the contract method 0x32424aa3.
//
// Solidity: function _decimals() view returns(uint8)
func (_BscUsdt *BscUsdtCaller) PrivateDecimals(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _BscUsdt.contract.Call(opts, &out, "_decimals")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// PrivateDecimals is a free data retrieval call binding the contract method 0x32424aa3.
//
// Solidity: function _decimals() view returns(uint8)
func (_BscUsdt *BscUsdtSession) PrivateDecimals() (uint8, error) {
	return _BscUsdt.Contract.PrivateDecimals(&_BscUsdt.CallOpts)
}

// PrivateDecimals is a free data retrieval call binding the contract method 0x32424aa3.
//
// Solidity: function _decimals() view returns(uint8)
func (_BscUsdt *BscUsdtCallerSession) PrivateDecimals() (uint8, error) {
	return _BscUsdt.Contract.PrivateDecimals(&_BscUsdt.CallOpts)
}

// PrivateName is a free data retrieval call binding the contract method 0xd28d8852.
//
// Solidity: function _name() view returns(string)
func (_BscUsdt *BscUsdtCaller) PrivateName(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _BscUsdt.contract.Call(opts, &out, "_name")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// PrivateName is a free data retrieval call binding the contract method 0xd28d8852.
//
// Solidity: function _name() view returns(string)
func (_BscUsdt *BscUsdtSession) PrivateName() (string, error) {
	return _BscUsdt.Contract.PrivateName(&_BscUsdt.CallOpts)
}

// PrivateName is a free data retrieval call binding the contract method 0xd28d8852.
//
// Solidity: function _name() view returns(string)
func (_BscUsdt *BscUsdtCallerSession) PrivateName() (string, error) {
	return _BscUsdt.Contract.PrivateName(&_BscUsdt.CallOpts)
}

// PrivateSymbol is a free data retrieval call binding the contract method 0xb09f1266.
//
// Solidity: function _symbol() view returns(string)
func (_BscUsdt *BscUsdtCaller) PrivateSymbol(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _BscUsdt.contract.Call(opts, &out, "_symbol")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// PrivateSymbol is a free data retrieval call binding the contract method 0xb09f1266.
//
// Solidity: function _symbol() view returns(string)
func (_BscUsdt *BscUsdtSession) PrivateSymbol() (string, error) {
	return _BscUsdt.Contract.PrivateSymbol(&_BscUsdt.CallOpts)
}

// PrivateSymbol is a free data retrieval call binding the contract method 0xb09f1266.
//
// Solidity: function _symbol() view returns(string)
func (_BscUsdt *BscUsdtCallerSession) PrivateSymbol() (string, error) {
	return _BscUsdt.Contract.PrivateSymbol(&_BscUsdt.CallOpts)
}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_BscUsdt *BscUsdtCaller) Allowance(opts *bind.CallOpts, owner common.Address, spender common.Address) (*big.Int, error) {
	var out []interface{}
	err := _BscUsdt.contract.Call(opts, &out, "allowance", owner, spender)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_BscUsdt *BscUsdtSession) Allowance(owner common.Address, spender common.Address) (*big.Int, error) {
	return _BscUsdt.Contract.Allowance(&_BscUsdt.CallOpts, owner, spender)
}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_BscUsdt *BscUsdtCallerSession) Allowance(owner common.Address, spender common.Address) (*big.Int, error) {
	return _BscUsdt.Contract.Allowance(&_BscUsdt.CallOpts, owner, spender)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_BscUsdt *BscUsdtCaller) BalanceOf(opts *bind.CallOpts, account common.Address) (*big.Int, error) {
	var out []interface{}
	err := _BscUsdt.contract.Call(opts, &out, "balanceOf", account)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_BscUsdt *BscUsdtSession) BalanceOf(account common.Address) (*big.Int, error) {
	return _BscUsdt.Contract.BalanceOf(&_BscUsdt.CallOpts, account)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_BscUsdt *BscUsdtCallerSession) BalanceOf(account common.Address) (*big.Int, error) {
	return _BscUsdt.Contract.BalanceOf(&_BscUsdt.CallOpts, account)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_BscUsdt *BscUsdtCaller) Decimals(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _BscUsdt.contract.Call(opts, &out, "decimals")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_BscUsdt *BscUsdtSession) Decimals() (uint8, error) {
	return _BscUsdt.Contract.Decimals(&_BscUsdt.CallOpts)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_BscUsdt *BscUsdtCallerSession) Decimals() (uint8, error) {
	return _BscUsdt.Contract.Decimals(&_BscUsdt.CallOpts)
}

// GetOwner is a free data retrieval call binding the contract method 0x893d20e8.
//
// Solidity: function getOwner() view returns(address)
func (_BscUsdt *BscUsdtCaller) GetOwner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _BscUsdt.contract.Call(opts, &out, "getOwner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetOwner is a free data retrieval call binding the contract method 0x893d20e8.
//
// Solidity: function getOwner() view returns(address)
func (_BscUsdt *BscUsdtSession) GetOwner() (common.Address, error) {
	return _BscUsdt.Contract.GetOwner(&_BscUsdt.CallOpts)
}

// GetOwner is a free data retrieval call binding the contract method 0x893d20e8.
//
// Solidity: function getOwner() view returns(address)
func (_BscUsdt *BscUsdtCallerSession) GetOwner() (common.Address, error) {
	return _BscUsdt.Contract.GetOwner(&_BscUsdt.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_BscUsdt *BscUsdtCaller) Name(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _BscUsdt.contract.Call(opts, &out, "name")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_BscUsdt *BscUsdtSession) Name() (string, error) {
	return _BscUsdt.Contract.Name(&_BscUsdt.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_BscUsdt *BscUsdtCallerSession) Name() (string, error) {
	return _BscUsdt.Contract.Name(&_BscUsdt.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_BscUsdt *BscUsdtCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _BscUsdt.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_BscUsdt *BscUsdtSession) Owner() (common.Address, error) {
	return _BscUsdt.Contract.Owner(&_BscUsdt.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_BscUsdt *BscUsdtCallerSession) Owner() (common.Address, error) {
	return _BscUsdt.Contract.Owner(&_BscUsdt.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_BscUsdt *BscUsdtCaller) Symbol(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _BscUsdt.contract.Call(opts, &out, "symbol")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_BscUsdt *BscUsdtSession) Symbol() (string, error) {
	return _BscUsdt.Contract.Symbol(&_BscUsdt.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_BscUsdt *BscUsdtCallerSession) Symbol() (string, error) {
	return _BscUsdt.Contract.Symbol(&_BscUsdt.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_BscUsdt *BscUsdtCaller) TotalSupply(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _BscUsdt.contract.Call(opts, &out, "totalSupply")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_BscUsdt *BscUsdtSession) TotalSupply() (*big.Int, error) {
	return _BscUsdt.Contract.TotalSupply(&_BscUsdt.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_BscUsdt *BscUsdtCallerSession) TotalSupply() (*big.Int, error) {
	return _BscUsdt.Contract.TotalSupply(&_BscUsdt.CallOpts)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtTransactor) Approve(opts *bind.TransactOpts, spender common.Address, amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.contract.Transact(opts, "approve", spender, amount)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtSession) Approve(spender common.Address, amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.Approve(&_BscUsdt.TransactOpts, spender, amount)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtTransactorSession) Approve(spender common.Address, amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.Approve(&_BscUsdt.TransactOpts, spender, amount)
}

// Burn is a paid mutator transaction binding the contract method 0x42966c68.
//
// Solidity: function burn(uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtTransactor) Burn(opts *bind.TransactOpts, amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.contract.Transact(opts, "burn", amount)
}

// Burn is a paid mutator transaction binding the contract method 0x42966c68.
//
// Solidity: function burn(uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtSession) Burn(amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.Burn(&_BscUsdt.TransactOpts, amount)
}

// Burn is a paid mutator transaction binding the contract method 0x42966c68.
//
// Solidity: function burn(uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtTransactorSession) Burn(amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.Burn(&_BscUsdt.TransactOpts, amount)
}

// DecreaseAllowance is a paid mutator transaction binding the contract method 0xa457c2d7.
//
// Solidity: function decreaseAllowance(address spender, uint256 subtractedValue) returns(bool)
func (_BscUsdt *BscUsdtTransactor) DecreaseAllowance(opts *bind.TransactOpts, spender common.Address, subtractedValue *big.Int) (*types.Transaction, error) {
	return _BscUsdt.contract.Transact(opts, "decreaseAllowance", spender, subtractedValue)
}

// DecreaseAllowance is a paid mutator transaction binding the contract method 0xa457c2d7.
//
// Solidity: function decreaseAllowance(address spender, uint256 subtractedValue) returns(bool)
func (_BscUsdt *BscUsdtSession) DecreaseAllowance(spender common.Address, subtractedValue *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.DecreaseAllowance(&_BscUsdt.TransactOpts, spender, subtractedValue)
}

// DecreaseAllowance is a paid mutator transaction binding the contract method 0xa457c2d7.
//
// Solidity: function decreaseAllowance(address spender, uint256 subtractedValue) returns(bool)
func (_BscUsdt *BscUsdtTransactorSession) DecreaseAllowance(spender common.Address, subtractedValue *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.DecreaseAllowance(&_BscUsdt.TransactOpts, spender, subtractedValue)
}

// IncreaseAllowance is a paid mutator transaction binding the contract method 0x39509351.
//
// Solidity: function increaseAllowance(address spender, uint256 addedValue) returns(bool)
func (_BscUsdt *BscUsdtTransactor) IncreaseAllowance(opts *bind.TransactOpts, spender common.Address, addedValue *big.Int) (*types.Transaction, error) {
	return _BscUsdt.contract.Transact(opts, "increaseAllowance", spender, addedValue)
}

// IncreaseAllowance is a paid mutator transaction binding the contract method 0x39509351.
//
// Solidity: function increaseAllowance(address spender, uint256 addedValue) returns(bool)
func (_BscUsdt *BscUsdtSession) IncreaseAllowance(spender common.Address, addedValue *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.IncreaseAllowance(&_BscUsdt.TransactOpts, spender, addedValue)
}

// IncreaseAllowance is a paid mutator transaction binding the contract method 0x39509351.
//
// Solidity: function increaseAllowance(address spender, uint256 addedValue) returns(bool)
func (_BscUsdt *BscUsdtTransactorSession) IncreaseAllowance(spender common.Address, addedValue *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.IncreaseAllowance(&_BscUsdt.TransactOpts, spender, addedValue)
}

// Mint is a paid mutator transaction binding the contract method 0xa0712d68.
//
// Solidity: function mint(uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtTransactor) Mint(opts *bind.TransactOpts, amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.contract.Transact(opts, "mint", amount)
}

// Mint is a paid mutator transaction binding the contract method 0xa0712d68.
//
// Solidity: function mint(uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtSession) Mint(amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.Mint(&_BscUsdt.TransactOpts, amount)
}

// Mint is a paid mutator transaction binding the contract method 0xa0712d68.
//
// Solidity: function mint(uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtTransactorSession) Mint(amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.Mint(&_BscUsdt.TransactOpts, amount)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_BscUsdt *BscUsdtTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _BscUsdt.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_BscUsdt *BscUsdtSession) RenounceOwnership() (*types.Transaction, error) {
	return _BscUsdt.Contract.RenounceOwnership(&_BscUsdt.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_BscUsdt *BscUsdtTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _BscUsdt.Contract.RenounceOwnership(&_BscUsdt.TransactOpts)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address recipient, uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtTransactor) Transfer(opts *bind.TransactOpts, recipient common.Address, amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.contract.Transact(opts, "transfer", recipient, amount)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address recipient, uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtSession) Transfer(recipient common.Address, amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.Transfer(&_BscUsdt.TransactOpts, recipient, amount)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address recipient, uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtTransactorSession) Transfer(recipient common.Address, amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.Transfer(&_BscUsdt.TransactOpts, recipient, amount)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address sender, address recipient, uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtTransactor) TransferFrom(opts *bind.TransactOpts, sender common.Address, recipient common.Address, amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.contract.Transact(opts, "transferFrom", sender, recipient, amount)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address sender, address recipient, uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtSession) TransferFrom(sender common.Address, recipient common.Address, amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.TransferFrom(&_BscUsdt.TransactOpts, sender, recipient, amount)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address sender, address recipient, uint256 amount) returns(bool)
func (_BscUsdt *BscUsdtTransactorSession) TransferFrom(sender common.Address, recipient common.Address, amount *big.Int) (*types.Transaction, error) {
	return _BscUsdt.Contract.TransferFrom(&_BscUsdt.TransactOpts, sender, recipient, amount)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_BscUsdt *BscUsdtTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _BscUsdt.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_BscUsdt *BscUsdtSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _BscUsdt.Contract.TransferOwnership(&_BscUsdt.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_BscUsdt *BscUsdtTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _BscUsdt.Contract.TransferOwnership(&_BscUsdt.TransactOpts, newOwner)
}

// BscUsdtApprovalIterator is returned from FilterApproval and is used to iterate over the raw logs and unpacked data for Approval events raised by the BscUsdt contract.
type BscUsdtApprovalIterator struct {
	Event *BscUsdtApproval // Event containing the contract specifics and raw log

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
func (it *BscUsdtApprovalIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BscUsdtApproval)
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
		it.Event = new(BscUsdtApproval)
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
func (it *BscUsdtApprovalIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BscUsdtApprovalIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BscUsdtApproval represents a Approval event raised by the BscUsdt contract.
type BscUsdtApproval struct {
	Owner   common.Address
	Spender common.Address
	Value   *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterApproval is a free log retrieval operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed spender, uint256 value)
func (_BscUsdt *BscUsdtFilterer) FilterApproval(opts *bind.FilterOpts, owner []common.Address, spender []common.Address) (*BscUsdtApprovalIterator, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var spenderRule []interface{}
	for _, spenderItem := range spender {
		spenderRule = append(spenderRule, spenderItem)
	}

	logs, sub, err := _BscUsdt.contract.FilterLogs(opts, "Approval", ownerRule, spenderRule)
	if err != nil {
		return nil, err
	}
	return &BscUsdtApprovalIterator{contract: _BscUsdt.contract, event: "Approval", logs: logs, sub: sub}, nil
}

// WatchApproval is a free log subscription operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed spender, uint256 value)
func (_BscUsdt *BscUsdtFilterer) WatchApproval(opts *bind.WatchOpts, sink chan<- *BscUsdtApproval, owner []common.Address, spender []common.Address) (event.Subscription, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var spenderRule []interface{}
	for _, spenderItem := range spender {
		spenderRule = append(spenderRule, spenderItem)
	}

	logs, sub, err := _BscUsdt.contract.WatchLogs(opts, "Approval", ownerRule, spenderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BscUsdtApproval)
				if err := _BscUsdt.contract.UnpackLog(event, "Approval", log); err != nil {
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
func (_BscUsdt *BscUsdtFilterer) ParseApproval(log types.Log) (*BscUsdtApproval, error) {
	event := new(BscUsdtApproval)
	if err := _BscUsdt.contract.UnpackLog(event, "Approval", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BscUsdtOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the BscUsdt contract.
type BscUsdtOwnershipTransferredIterator struct {
	Event *BscUsdtOwnershipTransferred // Event containing the contract specifics and raw log

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
func (it *BscUsdtOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BscUsdtOwnershipTransferred)
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
		it.Event = new(BscUsdtOwnershipTransferred)
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
func (it *BscUsdtOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BscUsdtOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BscUsdtOwnershipTransferred represents a OwnershipTransferred event raised by the BscUsdt contract.
type BscUsdtOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_BscUsdt *BscUsdtFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*BscUsdtOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _BscUsdt.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &BscUsdtOwnershipTransferredIterator{contract: _BscUsdt.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_BscUsdt *BscUsdtFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *BscUsdtOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _BscUsdt.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BscUsdtOwnershipTransferred)
				if err := _BscUsdt.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
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
func (_BscUsdt *BscUsdtFilterer) ParseOwnershipTransferred(log types.Log) (*BscUsdtOwnershipTransferred, error) {
	event := new(BscUsdtOwnershipTransferred)
	if err := _BscUsdt.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BscUsdtTransferIterator is returned from FilterTransfer and is used to iterate over the raw logs and unpacked data for Transfer events raised by the BscUsdt contract.
type BscUsdtTransferIterator struct {
	Event *BscUsdtTransfer // Event containing the contract specifics and raw log

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
func (it *BscUsdtTransferIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BscUsdtTransfer)
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
		it.Event = new(BscUsdtTransfer)
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
func (it *BscUsdtTransferIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BscUsdtTransferIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BscUsdtTransfer represents a Transfer event raised by the BscUsdt contract.
type BscUsdtTransfer struct {
	From  common.Address
	To    common.Address
	Value *big.Int
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterTransfer is a free log retrieval operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 value)
func (_BscUsdt *BscUsdtFilterer) FilterTransfer(opts *bind.FilterOpts, from []common.Address, to []common.Address) (*BscUsdtTransferIterator, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	logs, sub, err := _BscUsdt.contract.FilterLogs(opts, "Transfer", fromRule, toRule)
	if err != nil {
		return nil, err
	}
	return &BscUsdtTransferIterator{contract: _BscUsdt.contract, event: "Transfer", logs: logs, sub: sub}, nil
}

// WatchTransfer is a free log subscription operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 value)
func (_BscUsdt *BscUsdtFilterer) WatchTransfer(opts *bind.WatchOpts, sink chan<- *BscUsdtTransfer, from []common.Address, to []common.Address) (event.Subscription, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	logs, sub, err := _BscUsdt.contract.WatchLogs(opts, "Transfer", fromRule, toRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BscUsdtTransfer)
				if err := _BscUsdt.contract.UnpackLog(event, "Transfer", log); err != nil {
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
func (_BscUsdt *BscUsdtFilterer) ParseTransfer(log types.Log) (*BscUsdtTransfer, error) {
	event := new(BscUsdtTransfer)
	if err := _BscUsdt.contract.UnpackLog(event, "Transfer", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
