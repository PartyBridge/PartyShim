# PartyShim

PartyShim exists as a layer to seperate ownership of bridge contracts while still exposing an interface that `PartyBridge` can access.


## Overview


## Configure and Deploy

There is a pre-built docker image located at `gcr.io/mineonlium/partyshim` that you can use. Or feel free to build your own container image. 

Choose one of the following:

1/ Kubernetes deployment and service manifests are located in `config/shim.yaml`

1/ Docker compose file located in the root. 

1/ Bear metal execution of the binary.

After selecting one of the following you will need to provide your runtime with several enviorment variables:
       
       * CONTRACT_ADDRESS - This should point to the deployed contract on the OUTSIDE network.
       * PRIVATE_KEY - The private key that deployed the contract on the OUTSIDE network. 
       * DEFAULT_PAYMENT_PRIVATE_KEY - The private key that will be used if no private key is provided by `PartyBridge` at event time.
       * RPC_URL - This should point a RPC server for the WRAPPED asset. 
       * RPC_URL2 - This should point to a RPC server for the NATIVE currency. 
       * SHIM_CA_CERT - This should contain the location of of both the `cert.pem` and `key_pkcs1.pem` files. (I.E. `/home/jeff/cert`)


## Integrate a New Chain

Follow the steps below to integrate a new chain with `PartyBridge`:

1/ Deploy the contract located at `contract/bridge.sol` to the new chain. 

1/ Update `contract/deployments.md` with the contract address.

1/ PR this repository with the changes. 


## Development

Example request to the `/mint` route: 
```
curl -v "https://45.79.60.232/mint" \
       -X POST \
       -k \
       -H "Content-Type: application/json" \
       -d '{"amount": 10000, "toAddress":"0x5dd4039c32F6EEF427D6F67600D8920c9631D59D"}' \
       --cert ./client.crt \
       --key ./client.key
```


Example request to the `/transfer` route:

```
curl -v "https://0.0.0.0:8080/transfer" \
       -X POST \
       -k \
       -H "Content-Type: application/json" \
       -d '{"amount": 100000000000000000, "toAddress":"0x9cA67FFE69698d963A393E9338aD3BcfD2CEa02e","fromPK":""}' \
       --cert ./client.crt \
       --key ./client.key

curl -v "https://0.0.0.0:8080/transfer" \
       -X POST \
       -k \
       -H "Content-Type: application/json" \
       -d '{"amount": 10000, "toAddress":"0x5bbfa5724260Cb175cB39b24802A04c3bfe72eb3"}' \
       --cert ./client.crt \
       --key ./client.key
```






GPT suggestion for creating and adding authority to certs

First, create a configuration file named openssl.cnf with the following content:

```
[ req ]
default_bits        = 2048
default_keyfile     = server-key.pem
distinguished_name  = req_distinguished_name
req_extensions      = req_ext

[ req_distinguished_name ]
countryName                 = AU
stateOrProvinceName         = Some-State
localityName               = City
organizationName           = company
commonName                 = Internet Widgits Pty Ltd
commonName_max             = 64

[ req_ext ]
subjectAltName          = @alt_names

[alt_names]
DNS.1   = partyshim-wgrams
DNS.2   = partyshim-partychain-wocta
DNS.3   = partyshim-partychain-bscusdt
```


Make sure to replace the IP.1 and IP.2 values with the correct IP addresses.

Now, use the following commands to generate the self-signed certificate and add the subject alternative names:
```
# Generate the CA key and certificate
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt

# Generate the server key
openssl genrsa -out server.key 2048

# Create the server CSR using the configuration file
openssl req -new -key server.key -out server.csr -config openssl.cnf

# Sign the server CSR with the CA key and certificate, using the configuration file
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -extensions req_ext -extfile openssl.cnf


# Generate the client key and certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
```

After following these steps, your server certificate should include the subject alternative names, and the connection should work as expected.



base64 encode for the kubernetes secret

cat ca.crt | base64
cat client.crt | base64
cat client.key | base64
cat server.crt | base64
cat server.key | base64

