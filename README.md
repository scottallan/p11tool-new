# p11tool-new

   ## PKCS11 Tool to Create Keys
```
#build Tool


go build -o p11tool-new

#Help
```
```
p11tool-new -help
  -action string
        list,import,generateAndImport,generateSecret,getSKI (default "list")
  -keyFile string
        path to key you want to import or getSKI (default "/some/dir/key.pem")
  -keyLabel string
        Label of CKK_GENERIC_SECRET (default "tmpkey")
  -keyLen int
        Key Length for CKK_GENERIC_SECRET (32,48,...) (default 32)
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
