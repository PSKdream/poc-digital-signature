# POC Digital Signature

## Keytool

- Generate a new key pair and a self-signed certificate
```commandline
keytool -genkeypair \
    -alias pdf_signer \
    -keyalg RSA \
    -keysize 2048 \
    -sigalg SHA256withRSA \
    -dname "CN=Your Name, OU=Your Unit, O=Your Organization, L=Your City, ST=Your State, C=US" \
    -validity 365 \
    -keystore ./keystore.p12    
```

- List the content of the keystore
```commandline
keytool -list -keystore ./keystore.p12
```

- Create Intermediate CA with Root CA
1. Generate a Root CA Key and Certificate:
```commandline
keytool -genkeypair -alias rootca -keyalg RSA \
-keysize 2048 -validity 3650 -keystore rootca.p12 \
-storepass password -dname "CN=Root CA,OU=My Org,O=My Company,C=US"
```
2. Export the Root CA Certificate:
```commandline
keytool -exportcert -alias rootca -keystore rootca.p12 \
-file rootca.cer -storepass password
```
3. Generate an Intermediate CA Key and Certificate:
```commandline
keytool -genkeypair -alias intermediateca \
-keyalg RSA -keysize 2048 -validity 1825 \
 -keystore intermediateca.p12 -storepass password \
 -dname "CN=Intermediate CA,OU=My Org,O=My Company,C=US"
```
4. Create a Certificate Signing Request (CSR) for the Intermediate CA:
```commandline
keytool -certreq -alias intermediateca -keystore intermediateca.p12 \
-file intermediateca.csr -storepass password
```
5. Sign the Intermediate CA Certificate with the Root CA:
```commandline
keytool -gencert -alias rootca -keystore rootca.p12 -infile intermediateca.csr \
-outfile intermediateca.cer -storepass password -validity 1825
```
6. Import the Root CA Certificate into the Intermediate CA Keystore:
```commandline
keytool -importcert -alias rootca -keystore intermediateca.p12 \
-file rootca.cer -storepass password -noprompt
```
7. Import the Signed Intermediate CA Certificate:
```commandline
keytool -importcert -alias intermediateca -keystore intermediateca.p12 \
-file intermediateca.cer -storepass password
```
