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
