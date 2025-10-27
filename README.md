![certprobe gopher](docs/assets/certprobe-gopher.png)
# certprobe

**certprobe** is a command-line TLS/SSL certificate inspection tool.

It connects to a target host, retrieves the presented certificate chain, and reports trust, validity, key details, and common configuration issues. Supports system DNS and custom resolver overrides.

---

## Features

- Fetch adn display full certificate chains

- Trust verification
  Checks if the chain is trusted by the system trust store

- Validity checks  
  Highlights certificates that are expired, not yet valid, or near expiration.

- Key and signature details  
  Reports key length, algorithm, and signature scheme.

## Example Output

```console
Target: example.com (93.184.216.34)
TLS: TLS 1.3 / TLS_AES_256_GCM_SHA384
OCSP Stapling: No

- Certificate 0 (Leaf)
  Common Name (CN)             example.com
  subjectAltName (SAN)         example.com, www.example.com
  Trust                        OK
  Certificate Validity (UTC)   85 >= 60 days (2025-07-05 12:00 --> 2025-09-28 12:00)
  Signature Algorithm           SHA-256 with RSA
  Key Usage                    DigitalSignature, KeyEncipherment
  Extended Key Usage            ServerAuth, ClientAuth
  Serial                       9C1D0F212D8D924157EA2983052F5A0
  Fingerprint                  SHA1 1DD01214209A218FDE0F6DD354C72C61E753CD30
                               SHA256 C510B0382439895757C92CE5565D264E84DC08F6CFA696323B123D88FD5B8A47
  Issuer                       R3 (Let's Encrypt)

- Certificate 1 
  Common Name (CN)            R13
  subjectAltName (SAN)        
  Trust                       OK
  Certificate Validity (UTC)  501 >= 60 days (2024-03-13 00:00 --> 2027-03-12 23:59)
  Signature Algorithm         SHA-256 with RSA
  Key Usage                   CRL Sign, Digital Signature, Cert Sign
  Extended Key Usage          TLS Web Client Authentication, TLS Web Server Authentication
  Serial                      5A00F212D8D4B480F3924157EA298305
  Fingerprint                 SHA1 22FF89586561FC2D52F77491E9F1EFF1B80BE33E
                              SHA256 D3B128216A843F8EF1321501F5DF52A5DF52939EE2C19297712CD3DE4D419354
  Issuer                      ISRG Root X1 (Internet Security Research Group)