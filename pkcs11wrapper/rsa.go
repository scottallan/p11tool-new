package pkcs11wrapper

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

type RsaKey struct {
	PubKey       *rsa.PublicKey
	PrivKey      *rsa.PrivateKey
	SKI          SubjectKeyIdentifier
	PrivKeyBlock *pem.Block
	keyLabel     string
	Certificate  []*x509.Certificate
	ephemeral    bool
	Token        bool
	rsaKeySize   int
}

// SKI returns the subject key identifier of this key.
func (k *RsaKey) GenSKI() {
	if k.PubKey == nil {
		return
	}

	// get raw public key
	raw := k.PubKey.N.Bytes()

	// Hash it
	b32 := sha256.Sum256(raw)
	k.SKI.Sha256Bytes = b32[:]
	k.SKI.Sha256 = hex.EncodeToString(k.SKI.Sha256Bytes)
	b20 := sha1.Sum(raw)
	k.SKI.Sha1Bytes = b20[:]
	k.SKI.Sha1 = hex.EncodeToString(k.SKI.Sha1Bytes)

	return
}

func (k *RsaKey) Generate(bits int) (err error) {

	// generate private key
	k.PrivKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}

	// store public key
	k.PubKey = &k.PrivKey.PublicKey

	return
}

func (k *RsaKey) ImportPrivKeyFromFile(file string) (err error) {

	keyFile, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	keyBlock, _ := pem.Decode(keyFile)

	switch keyBlock.Type {
	// PKCS1 key
	case "RSA PRIVATE KEY":
		k.PrivKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return
		}
	// PKCS8 key
	case "PRIVATE KEY":
		pk8Key, pk8Err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if pk8Err != nil {
			return pk8Err
		}
		k.PrivKey = pk8Key.(*rsa.PrivateKey)
	// UNSUPPORTED
	default:
		err = fmt.Errorf("unsupported key type: %v", keyBlock.Type)
		return
	}

	// store public key
	k.PubKey = &k.PrivKey.PublicKey
	k.PrivKeyBlock = keyBlock

	return
}

func (k *RsaKey) SignMessage(message string, shaSize int) (signature string, err error) {

	var digest []byte
	var hash crypto.Hash
	switch shaSize {

	case 256:
		d := sha256.Sum256([]byte(message))
		digest = d[:]
		hash = crypto.SHA256

	case 384:
		d := sha512.Sum384([]byte(message))
		digest = d[:]
		hash = crypto.SHA384

	case 512:
		d := sha512.Sum512([]byte(message))
		digest = d[:]
		hash = crypto.SHA512

	default:
		d := sha256.Sum256([]byte(message))
		digest = d[:]
		hash = crypto.SHA256

	}

	// sign the hash
	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, k.PrivKey, hash, digest)
	if err != nil {
		return
	}

	signature = hex.EncodeToString(signatureBytes)

	return
}
