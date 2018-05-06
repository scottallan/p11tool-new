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

./p11too-new -action generateCSR -csrInfo contrib/consolidated.json -keyType EC  -keyLabel bfab4fe413c945ade535fe6c85d6a3b61a2c0b83c0671c1c24066ce1cad12827 -slot slot -pin 1234 -lib /usr/safenet/lunaclient/lib/libCryptoki2_64.so

This will output a CSR request into your working directory call out.pem.

you can validate this CSR with openssl using the following syntax:

openss req -in out.pem -text

Once you confirm that you have generated a valid CSR with the correct dname and common name you can then submit to a certificate authority to retreive a Certificate.