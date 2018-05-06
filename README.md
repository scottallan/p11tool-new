# p11tool-new

   ## PKCS11 Tool to Create Keys
```
#build Tool


go build -o p11tool-new

#Help
```
```
./p11too-new -help
  -action string
    	list,import,generate,generateAndImport,generateSecret,getSKI,SignHMAC384,generateCSR,importCert (default "list")
  -allow_verification_with_non_compliant_keys
    	Allow a SignatureVerifier to use keys which are technically non-compliant with RFC6962.
  -csrInfo string
    	json file with values for CSR Creation
  -keyFile string
    	path to key you want to import or getSKI (default "/some/dir/key.pem")
  -keyLabel string
    	Label of CKK_GENERIC_SECRET (default "tmpkey")
  -keyLen int
    	Key Length for CKK_GENERIC_SECRET (32,48,...) (default 32)
  -keyStore string
    	Keystore Type (file,pkcs12) (default "file")
  -keyStorepass string
    	Keystore Storepass (default "securekey")
  -keyType string
    	Type of key (EC,RSA,GENERIC_SECRET,AES) (default "EC")
  -lib string
    	Location of pkcs11 library
  -pin string
    	Slot PIN (default "98765432")
  -slot string
    	Slot Label (default "ForFabric")
  -outFile string
      output file for CSR Generation (default ./out.pem)
```
```
#Generate CKK_GENERIC_SECRET of 384 bit Length example
 ./p11tool-new -action generateSecret -keyLabel scott -keyLen 48 -keyType GENERIC_SECRET -lib /usr/safenet/lunaclient/lib/libCryptoki2_64.so -slot slot -pin 1234
```
```
PKCS11 provider found specified slot label: myvmeslot (slot: 0, index: 0)
Successfully tested CKM_SHA384_HMAC on key with label: scott
 HMAC 61d7474f05a421c968c67940ec49e7710bae9771c78039ee8a466b6e8789dfeccec6ffec880d20630299a9ffd2dfb30d
+-------+----------------+-----------+--------+--------------------+--------------------+
| COUNT |   CKA CLASS    | CKA LABEL | CKA ID |    CKA KEY TYPE    |    CKA KEY LEN     |
+-------+----------------+-----------+--------+--------------------+--------------------+
|   001 | CKO_SECRET_KEY | scott     |        | CKK_GENERIC_SECRET | [48 0 0 0 0 0 0 0] |
+-------+----------------+-----------+--------+--------------------+--------------------+
Total objects found (max 50): 1
```
```
#Generate CKK_EC key pair of NIST Curve p-256
./p11tool-new -action generate -keyType EC  -slot slot -pin 1234 -lib  /usr/safenet/lunaclient/lib/libCryptoki2_64.so 
```
```
#View the newly created Key and note the CKA_ID for the keys.  The Public and Private key will have the same CKA_ID.
./p11tool-new -action list -slot slot -pin 1234 -lib /usr/safenet/lunaclient/lib/libCryptoki2_64.so
```
```
PKCS11 provider found specified slot label: myvmeslot (slot: 498477766, index: 0)
+-------+-----------------+------------------------------------------------------------------+------------------------------------------------------------------+--------------+-------------+-------------+------------+
| COUNT |    CKA CLASS    |                            CKA LABEL                             |                              CKA ID                              | CKA KEY TYPE | CKA KEY LEN | CKA SUBJECT | CKA ISSUER |
+-------+-----------------+------------------------------------------------------------------+------------------------------------------------------------------+--------------+-------------+-------------+------------+
|   001 | CKO_PUBLIC_KEY  | bfab4fe413c945ade535fe6c85d6a3b61a2c0b83c0671c1c24066ce1cad12827 | bfab4fe413c945ade535fe6c85d6a3b61a2c0b83c0671c1c24066ce1cad12827 | CKK_ECDSA    |           0 |             |            |
|   002 | CKO_PRIVATE_KEY | bfab4fe413c945ade535fe6c85d6a3b61a2c0b83c0671c1c24066ce1cad12827 | bfab4fe413c945ade535fe6c85d6a3b61a2c0b83c0671c1c24066ce1cad12827 | CKK_ECDSA    |           0 |             |            |
+-------+-----------------+------------------------------------------------------------------+------------------------------------------------------------------+--------------+-------------+-------------+------------+
```
```
#Generate CSR for new keys
- You need to modify the contrib/consolidated.json file to provide the correct CSR Information for you cert.

the file by default provides:
{
	  "hosts":[ "scott.gemalto.securekey.com", "scottdev.gemalto.securekey.com" ],
	  "names":[ {
		      "c":"CA",
		      "st":"ONT",
		      "l":"TORONTO",
		      "o":"OPS",
		      "ou":"GemaltoLuna"
		    }
                  ],
	  "CN":"scott.gemaltotest.securekey.com"
}
```
You will need to modify the CN (Common Name) and also modify the the dName fields (names) as appropriate for your org.
the hosts entries are the SANs (Subject Alternative Names) for the cert.  You can leave this blank if you wish.
```
You will need the CKA_ID from the Generate command.  In the example this is given as the value bfab4fe413c945ade535fe6c85d6a3b61a2c0b83c0671c1c24066ce1cad12827
Once you have modifed the json file you can generate the CSR with the following command:

./p11too-new -action generateCSR -csrInfo contrib/consolidated.json -keyType EC  -keyLabel bfab4fe413c945ade535fe6c85d6a3b61a2c0b83c0671c1c24066ce1cad12827 -slot slot -pin 1234 -lib /usr/safenet/lunaclient/lib/libCryptoki2_64.so -keyFile out.pem

This will output a CSR request into your working directory call out.pem.

you can validate this CSR with openssl using the following syntax:

openss req -in out.pem -text

Once you confirm that you have generated a valid CSR with the correct dname and common name you can then submit to a certificate authority to retreive a Certificate.
```
```
#Importing the Certificate chain produced for the CSR by a CA
Once you recieve the Certificate bundle you should prepare a single PEM with the chain of certificates.  An example would be as below where the top entry is the Cert and the second entry the CA.  If there was an intermediate CA you would have more entries such as CERT -> Intermediate -> Root CA:

-----BEGIN CERTIFICATE-----
MIIDhTCCAW0CCQCFynHcBdbLSDANBgkqhkiG9w0BAQsFADBZMQswCQYDVQQGEwJD
QTEQMA4GA1UECAwHT05UQVJJTzEQMA4GA1UEBwwHVE9ST05UTzEMMAoGA1UECgwD
T1BTMQswCQYDVQQLDAJDQTELMAkGA1UEAwwCQ0EwHhcNMTgwNTA2MDEwMjEwWhcN
MTgwNjA1MDEwMjEwWjB7MQswCQYDVQQGEwJDQTEMMAoGA1UECBMDT05UMRAwDgYD
VQQHEwdUT1JPTlRPMQwwCgYDVQQKEwNPUFMxFDASBgNVBAsTC0dlbWFsdG9MdW5h
MSgwJgYDVQQDEx9zY290dC5nZW1hbHRvdGVzdC5zZWN1cmVrZXkuY29tMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEltM2pbxuDFcIBMS2/5T1sFMlt5ms02Opk++1
aA1KOzroprqaZhyhCU6ZLBYcLvJuVRx6PhQ+dND2mpJtW0i1ZDANBgkqhkiG9w0B
AQsFAAOCAgEAPu9JTq0WXfsklgpubDOISQ+xPYipnJcjqhsPe8eDc+dKbwMqYhUK
ByXf2lLL2gvp3G4rsq30zb8KG4mAsxP4o0lfXpQZslPUvsnrCzvmHUlUOn7emGae
6RkaJBXTprVIx4RWO1AuKP3DaUAaQdHDastiL8yTQTznHgtNQmUyN15n23JZ2pLv
8bd+rL31l2lCz6vfbTJJoM9zb/VUPmi1rN1f5OYme4J9NxdfdDhbm9pKRU6Rt3DO
uavcA3avl3eNcBBPbWvlu2QnDkS+M+pYXuk8owSaM0sortVreW5y4CMuFW7v9uVL
YBe/qYmvlk6yR7zqejv/AjDt5+30g6V4LxyffPqiQ6RpM+WVTZHFrY1D0aLrjshZ
9M/r+Kmmkp7N/EQxNfUfJLoHgaG4r56u1O3AhF0rd7V1zIeyyQ/ZQ/rdZVFfb7GR
ncc7ri2eZaR1q99LZsMqxY9JYqe21XrhC+XtgU7lDB1OzcvID73fE2Y0o+jDX3bG
cah/5kAFa5J5LCECFiRV7basmxRf4HA8ABh4WpmtCSJR7eR1/lH+tgDZ8exg3QFy
+1Q6Cw9lx8rxGb0rYeV9AKW+kK9n1TLLqosFojXeB8OHNw5mauJG7WASE95VO2A2
nL1LS08MhAQIfJcZflx1kNQRSkgBpgWDZ09NA8xk5hMgn7PcD1LTfa0=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFhTCCA22gAwIBAgIJAJyNxpa536j2MA0GCSqGSIb3DQEBCwUAMFkxCzAJBgNV
BAYTAkNBMRAwDgYDVQQIDAdPTlRBUklPMRAwDgYDVQQHDAdUT1JPTlRPMQwwCgYD
VQQKDANPUFMxCzAJBgNVBAsMAkNBMQswCQYDVQQDDAJDQTAeFw0xODA1MDUwNjQ2
MDFaFw0xODA2MDQwNjQ2MDFaMFkxCzAJBgNVBAYTAkNBMRAwDgYDVQQIDAdPTlRB
UklPMRAwDgYDVQQHDAdUT1JPTlRPMQwwCgYDVQQKDANPUFMxCzAJBgNVBAsMAkNB
MQswCQYDVQQDDAJDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL28
G+23vR+ICOb2wAVD4yWvC883HSFmDmgQPz4ad826C2+ePNDshv96yMD7yb7uclqa
egHnFjYF1SckjmWEzeLztFQ889aCJLIkp7Xu1jNBtQQLDo0rRoITq0SzpMyKdLPy
NuV8xQK6K425M/SOb6JBuc1q+PMGyEmWK28TNz+egl+L4SCKhdrGZzmln4RJyPBt
LC9/mgKbvWw9HsR+4vdBAuzOA/4ZxN6FD2avzaxPiytOOvQx/WjxkHhlw0CV/w/d
gjc/52J1XfhpVoMtHv8jQVC7qgegrds0qkPBFlMRcx5wSfYy9qe+nIyqlFUrGfas
5PR1MceawldMyQaDN1jMDeLvPvxhgyNduN9DqjX+lCzuIB7CPepuwH/fEL4VDOm+
I7IG0YeUeFm97tdk4RFAVFbg3CDpqgwzNcIukPXlWghAKK49AWjhaCVbttMZjCtn
KNKFg1nRwgoMnb8HeDzaeyIZmZmJKUXM4cpKKTXEV920HWt2Lz18CY4VrFp5gIKX
gJNe71svkDoLG83q4DmbLSwfpi/nHPj/liHzEXgK1wHtQtjPty3UDJQrak3zocu9
Cadeupk1ESuiKNvivQuHt04P4J15/OygDJ0SzwRwmlzvSrEE6l3rfAy+f01OX/+A
BUhYrIfzMN5T2bRBaDFqiZlDrU33JRfI1sJS5TDnAgMBAAGjUDBOMB0GA1UdDgQW
BBRAfPoHie06A+59Ug9nnR4Qhae0GjAfBgNVHSMEGDAWgBRAfPoHie06A+59Ug9n
nR4Qhae0GjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQCg4tgoeewu
eujddTHiYtvqFbX3iOTnj3UXXpwYVuwR4IPFjNrmN7nFi8iknu3q1nBQ1bIWqLt4
QBmvtnwRHimx17L5yEvXh940xsQzX7qcsu9yBQL02vnO4OFE2MVIT1S+6NdyfHya
wHoagbxtOK6LtZ9noTDpQOuh45azOzZ2gRVuLy5WSR33IuLnEnpya9H7uNZ6wpsX
o6a1tXXKJkBYjQqag+ioGlVR0XC6LLiNmFce2Ti4+9UcKhVHNYecM98jicTB9Z02
ncaqzMEHugS8k15ltrMSiRIH9vrvC9BPGhyoZ8CiQvMOTXObE7c9msh/bkNHXUSG
jrJmOXkT/0s5sUEQrYAmuOgEYA46XWBXQpTzFq/CbwD+oKSgyJpaHyLRRAIEdZbp
GwthkNb6aWgLjEbrfBC+Bk6wrdAD3z2IctEMy8qHg+cxT+gaSYVtxsh+V2B0YqY1
3MfrNRDOea2UJZYR3w3ja4QEWwqapQtxBFn3sW2UmikOS51E86WwVdFwEMHrFYcG
4NsYWMG+oJiuaOIsgOk7ytMyZaLxUx7vvpueyy1J8ev/c9wHD5lVYCsRgw8KgKiH
pBth+IUPyUTqzCNz7J+4ZxZA/dA7rWDew1mHM0w1cXOyu2V/BJpDj/B6NlcLlsSJ
gpxYw8z2HMFeW7DO8vN4GB5WLAU3tNm8sg==
-----END CERTIFICATE-----
```
Once you have the pem created you can import as follows:

./p11tool-new -action importCert -keyFile bundle.pem -keyLabel 28cea9ea528e85f74b734b2d74ab462570af6dfb6e91104c1ad58c348fc4c70c -keyType EC -lib /usr/safenet/lunaclient/lib/libCryptoki2_64.so -slot myvmeslot -pin 1234

```
A further listing on the slot should show you the Keys and the Certs in the HSM:
./p11tool-new -action list -slot slot -pin 1234 -lib /usr/safenet/lunaclient/lib/libCryptoki2_64.so

PKCS11 provider found specified slot label: myvmeslot (slot: 0, index: 0)
+-------+-----------------+------------------------------------------------------------------+------------------------------------------------------------------+--------------+-------------+-------------+------------+
| COUNT |    CKA CLASS    |                            CKA LABEL                             |                              CKA ID                              | CKA KEY TYPE | CKA KEY LEN | CKA SUBJECT | CKA ISSUER |
+-------+-----------------+------------------------------------------------------------------+------------------------------------------------------------------+--------------+-------------+-------------+------------+
|   001 | CKO_CERTIFICATE | scott.gemaltotest.securekey.com                                  | 28cea9ea528e85f74b734b2d74ab462570af6dfb6e91104c1ad58c348fc4c70c | CERTIFICATE  |           0 |             |            |
|   002 | CKO_CERTIFICATE | CA                                                               | 407cfa0789ed3a03ee7d520f679d1e1085a7b41a                         | CERTIFICATE  |           0 |             |            |
|   003 | CKO_PUBLIC_KEY  | 28cea9ea528e85f74b734b2d74ab462570af6dfb6e91104c1ad58c348fc4c70c | 28cea9ea528e85f74b734b2d74ab462570af6dfb6e91104c1ad58c348fc4c70c | CKK_ECDSA    |           0 |             |            |
|   004 | CKO_PRIVATE_KEY | 28cea9ea528e85f74b734b2d74ab462570af6dfb6e91104c1ad58c348fc4c70c | 28cea9ea528e85f74b734b2d74ab462570af6dfb6e91104c1ad58c348fc4c70c | CKK_ECDSA    |           0 |             |            |
+-------+-----------------+------------------------------------------------------------------+------------------------------------------------------------------+--------------+-------------+-------------+------------+
