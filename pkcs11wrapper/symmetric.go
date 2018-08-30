package pkcs11wrapper

import (
	"github.com/miekg/pkcs11"
	"os"
	"strconv"
	"bytes"
)

func (p11w *Pkcs11Wrapper) CreateSymKey(objectLabel string, keyLen int, keyType string) (aesKey pkcs11.ObjectHandle, err error) {

	var pkcs11_mech *pkcs11.Mechanism
	switch keyType {
	case "AES":
		pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)
	case "GENERIC_SECRET":
		pkcs11_mech = pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil)
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

/* return a set of attributes that we require for our aes key */
func (p11w *Pkcs11Wrapper) GetSymPkcs11Template(objectLabel string, keyLen int, keyType string) (SymPkcs11Template []*pkcs11.Attribute) {

	// default CKA_KEY_TYPE
	var pkcs11_keytype *pkcs11.Attribute
	switch keyType {
	case "AES":
		pkcs11_keytype = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES)
	case "GENERIC_SECRET":
		pkcs11_keytype = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET)
	default:
		pkcs11_keytype = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET)
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

	// Scott's Reference
	// default template common to all manufactures
	SymPkcs11Template = []*pkcs11.Attribute{
		// common to all
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),      /* Name of Key */
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),             /* This key should persist */
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, SymKeyLength), /* KeyLength */
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		// vendor specific override
		pkcs11_keytype,
	}
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
func (p11w *Pkcs11Wrapper) EncAESGCM(o pkcs11.ObjectHandle, message []byte) (enc []byte, IV []byte,  err error) {

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
	IV = enc[0:16]
	result := bytes.Join([][]byte{gcparams.IV(), enc}, nil)
	gcparams.Free()

	return result, IV, nil
}

// DecAESGCM test CKM_AES_GCM for Decryption
func (p11w *Pkcs11Wrapper) DecAESGCM(o pkcs11.ObjectHandle, ciphertext []byte, IV []byte) (message []byte, err error) {

	return
}

