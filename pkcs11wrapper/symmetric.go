package pkcs11wrapper

import (
	"bytes"
	"math/big"
	"os"
	"strconv"

	"github.com/miekg/pkcs11"
)

//ImportSymKey allows the importing of Symmetric Keys
func (p11w *Pkcs11Wrapper) ImportSymKey(keyType string, key string, keyStore string, keyStorePass string, keyLabel string) (err error) {

	n := new(big.Int)
	n, ok := n.SetString(key, 16)
	if !ok {
		ExitWithMessage("BigInt SetString:", nil)
	}

	getAttr := p11w.GetSymPkcs11Template(keyLabel, len(key), keyType)
	pkcs11KeyValue := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, n.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
	}
	getAttr = append(getAttr, pkcs11KeyValue...)
	_, err = p11w.Context.CreateObject(
		p11w.Session,
		getAttr,
	)
	if err != nil {
		ExitWithMessage("Unable to Import Key", err)
	}
	return

}

func (p11w *Pkcs11Wrapper) CreateSymKey(objectLabel string, keyLen int, keyType string) (aesKey pkcs11.ObjectHandle, err error) {

	var pkcs11_mech *pkcs11.Mechanism
	switch keyType {
	case "AES":
		pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)
	case "GENERIC_SECRET":
		pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil)
	case "DES3":
		pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_DES3_KEY_GEN, nil)
	case "SHA256_HMAC":
		if CaseInsensitiveContains(p11w.Library.Info.ManufacturerID, "ncipher") {
			pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_NC_SHA256_HMAC_KEY_GEN, nil)
		} else {
			pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil)
		}
	case "SHA384_HMAC":
		if CaseInsensitiveContains(p11w.Library.Info.ManufacturerID, "ncipher") {
			pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_NC_SHA384_HMAC_KEY_GEN, nil)
		} else {
			pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil)
		}
	default:
		pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil)
	}
	// default mech CKM_AES_KEY_GEN
	//pkcs11_mech := pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)

	// Overrides env first, then autodetect from vendor
	//switch {
	//case CaseInsensitiveContains(os.Getenv("SECURITY_PROVIDER_CONFIG_MECH"), "CKM_GENERIC_SECRET_KEY_GEN"):
	//       pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil)
	//case CaseInsensitiveContains(p11w.Library.Info.ManufacturerID, "SafeNet"):
	//       pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil)
	//}

	// get the required attributes
	requiredAttributes := p11w.GetSymPkcs11Template(objectLabel, keyLen, keyType)

	// generate the aes key
	aesKey, err = p11w.Context.GenerateKey(
		p11w.Session,
		[]*pkcs11.Mechanism{
			// vendor specific
			pkcs11_mech,
		},
		requiredAttributes,
	)
	if err != nil {
		ExitWithMessage("GenerateKey", err)
	}

	return
}

//WrapSymKey is used to wrap a non HSM protected symmetric key with a HSM protected wrapping key
func (p11w *Pkcs11Wrapper) WrapSymKey(keyType string, key string, keyLen int, w pkcs11.ObjectHandle) (wrappedKey []byte, err error) {
	
	if key == nil {
		err = errors.New("No Key Found To Wrap")
	}

	n := new(big.Int)
	
	n, ok := n.SetString(key, 16)
	if !ok {
		ExitWithMessage("BigInt SetString:", nil)
	}
	fmt.Printf("Setting Key to %v from string %s", n, key)
	err = p11w.Context.EncryptInit(
		p11w.Session,
		[]*pkcs11.Mechanism{
				//pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC,make([]byte, 8)),
				pkcs11.NewMechanism(pkcs11.CKM_DES3_CBC_PAD, make([]byte, 8)),
		},
		w, //Wrapping Key
	)
	if err != nil {
			fmt.Printf("Unable to Initialise Encryptor %v with key %v", err, w)
			return nil, err
	}
	wrappedKey, err = p11w.Context.Encrypt(
			p11w.Session,
			//ec.pk8.PrivateKey,
			key,
	)
	if err != nil {
			fmt.Printf("Unable to Encrypt Key : %v", err)
			return nil, err
	}

	fmt.Printf("Wrapped Key with CKM_DES3_CBS with wrappedKey %v from SymKey %v\n", wrappedKey, key)

	return
}

fun (p11w *Pkcs11Wrapper) UnwrapSymKey(wrappedKey []byte, w pkcs11.ObjectHandle, keyLable string) (err error) {

	return
}

/* return a set of attributes that we require for our aes key */
func (p11w *Pkcs11Wrapper) GetSymPkcs11Template(objectLabel string, keyLen int, keyType string) (SymPkcs11Template []*pkcs11.Attribute) {

	// default CKA_KEY_TYPE
	var pkcs11VendorAttr []*pkcs11.Attribute
	var pkcs11KeyType []*pkcs11.Attribute
	// Overrides Key Length
	SymKeyLength := keyLen
	pkcs11_keylen := os.Getenv("SECURITY_PROVIDER_CONFIG_KLEN")
	if len(pkcs11_keylen) > 0 {
		KeyLength, err := strconv.Atoi(pkcs11_keylen)
		if err != nil {
			return
		}
		SymKeyLength = KeyLength
	}
	switch keyType {
	case "AES":
		pkcs11KeyType = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		}
		pkcs11VendorAttr = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, SymKeyLength), /* KeyLength */
		}
		pkcs11VendorAttr = append(pkcs11VendorAttr, pkcs11KeyType...)
	case "DES3":

		pkcs11KeyType = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DES3),
		}
		if SymKeyLength != 0 { //CloudHSM and SoftHSM does not set keyLen on DES3...
			pkcs11VendorAttr = []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
				pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
				pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
				pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
				pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
				pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, SymKeyLength), /* KeyLength */
			}
		} else {
			pkcs11VendorAttr = []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
				pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
				pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
				pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
				pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
				pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
			}
		}
		pkcs11VendorAttr = append(pkcs11VendorAttr, pkcs11KeyType...)
	case "GENERIC_SECRET":
		pkcs11KeyType = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		}
		pkcs11VendorAttr = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, SymKeyLength), /* KeyLength */
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		}
		pkcs11VendorAttr = append(pkcs11VendorAttr, pkcs11KeyType...)
	case "SHA256_HMAC":
		if CaseInsensitiveContains(p11w.Library.Info.ManufacturerID, "ncipher") {
			pkcs11KeyType = []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_SHA256_HMAC),
			}
		} else {
			pkcs11KeyType = []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
			}
		}
		pkcs11VendorAttr = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, SymKeyLength), /* KeyLength */
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		}
		pkcs11VendorAttr = append(pkcs11VendorAttr, pkcs11KeyType...)
	case "SHA384_HMAC":
		if CaseInsensitiveContains(p11w.Library.Info.ManufacturerID, "ncipher") {
			pkcs11KeyType = []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_SHA384_HMAC),
			}
		} else {
			pkcs11KeyType = []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
			}
		}
		pkcs11VendorAttr = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, SymKeyLength), /* KeyLength */
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		}
		pkcs11VendorAttr = append(pkcs11VendorAttr, pkcs11KeyType...)
	default:
		pkcs11KeyType = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		}
		pkcs11VendorAttr = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, SymKeyLength), /* KeyLength */
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		}
		pkcs11VendorAttr = append(pkcs11VendorAttr, pkcs11KeyType...)
	}

	// Overrides env first, then autodetect from vendor
	//switch {
	//case CaseInsensitiveContains(os.Getenv("SECURITY_PROVIDER_CONFIG_KEYTYPE"), "CKK_GENERIC_SECRET"):
	//       pkcs11_keytype = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET)
	//case CaseInsensitiveContains(p11w.Library.Info.ManufacturerID, "softhsm") &&
	//      p11w.Library.Info.LibraryVersion.Major > 1 &&
	//     p11w.Library.Info.LibraryVersion.Minor > 2:
	// matches softhsm versions greater than 2.2 (scott patched 2.3)
	//      pkcs11_keytype = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET)
	//case CaseInsensitiveContains(p11w.Library.Info.ManufacturerID, "ncipher"):
	//      pkcs11_keytype = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_SHA256_HMAC)
	//case CaseInsensitiveContains(p11w.Library.Info.ManufacturerID, "SafeNet"):
	//      pkcs11_keytype = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET)
	//}

	// Scott's Reference
	// default template common to all manufactures

	SymPkcs11Template = []*pkcs11.Attribute{
		// common to all
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel), /* Name of Key */
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),        /* This key should persist */
		//pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, SymKeyLength), /* KeyLength */
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		// vendor specific override
	}
	SymPkcs11Template = append(SymPkcs11Template, pkcs11VendorAttr...)
	return
}

/* test CKM_SHA384_HMAC signing */
func (p11w *Pkcs11Wrapper) SignHmacSha384(o pkcs11.ObjectHandle, message []byte) (hmac []byte, err error) {

	// start the signing
	err = p11w.Context.SignInit(
		p11w.Session,
		[]*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_SHA384_HMAC, nil),
		},
		o,
	)
	if err != nil {
		return
	}

	// do the signing
	hmac, err = p11w.Context.Sign(p11w.Session, message)
	if err != nil {
		return
	}

	return
}

// EncAESGCM test CKM_AES_GCM for encryption
func (p11w *Pkcs11Wrapper) EncAESGCM(o pkcs11.ObjectHandle, message []byte) (enc []byte, IV []byte, err error) {

	//gcparams := pkcs11.NewGCMParams(make([]byte, 16), nil, 128)
	gcparams := pkcs11.NewGCMParams([]byte{}, nil, 128)
	err = p11w.Context.EncryptInit(
		p11w.Session,
		[]*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcparams),
		},
		o,
	)
	if err != nil {
		return
	}

	// do the encryption
	enc, err = p11w.Context.Encrypt(p11w.Session, message)
	if err != nil {
		return
	}
	//IV = enc[0:16]
	//IV is appended to End in Gemalto
	IV = enc[len(enc)-16:]
	result := bytes.Join([][]byte{gcparams.IV(), enc}, nil)
	//the above results in the join as equal to enc as IV() returns nil for Gemalto Testing
	gcparams.Free()

	return result, IV, nil
}

// DecAESGCM test CKM_AES_GCM for Decryption
func (p11w *Pkcs11Wrapper) DecAESGCM(o pkcs11.ObjectHandle, cipherText []byte, IV []byte) (message []byte, err error) {

	//gcparams := pkcs11.NewGCMParams(make([]byte, 16), nil, 128)
	gcparams := pkcs11.NewGCMParams(IV, nil, 128)
	err = p11w.Context.DecryptInit(
		p11w.Session,
		[]*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcparams),
		},
		o,
	)
	if err != nil {
		return nil, err
	}
	cipherText = cipherText[:len(cipherText)-16]
	message, err = p11w.Context.Decrypt(p11w.Session, cipherText)
	if err != nil {
		return nil, err
	}
	gcparams.Free()

	return
}
