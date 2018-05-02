package pkcs11wrapper

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/miekg/pkcs11"
	"github.com/olekukonko/tablewriter"
)

type Pkcs11Library struct {
	Path string
	Info pkcs11.Info
}

type Pkcs11Wrapper struct {

	// Context
	Library Pkcs11Library
	Context *pkcs11.Ctx

	// Session Handler
	SlotLabel string
	Session   pkcs11.SessionHandle

	// Optional Slot Login
	SlotPin string
}

type Pkcs11Object struct {
	ObjectHandle pkcs11.ObjectHandle

	// Some human readable attributes
	Count     string
	CKA_CLASS string
	CKA_LABEL string
	CKA_ID    string

}

// A BasicP11Request contains the algorithm and key size for a new CSR Generation.
type BasicP11Request struct {
	A string `json:"algo" yaml:"algo"`
	S int    `json:"size" yaml:"size"`
}

type Key interface {

	// SKI returns the subject key identifier of this key.
	GenSKI()
	/*
	Fix Function to be Generic
	Generate()
	*/ 
}

const (
	privateKeyFlag = true
	publicKeyFlag  = false
)

// maps used to convert object into human readable text
var CKA_KEY_TYPE_MAP map[byte]string
var CKA_CLASS_MAP map[uint]string

func init() {

	// set up values for CKA_KEY_TYPE
	CKA_KEY_TYPE_MAP = map[byte]string{
		pkcs11.CKK_GENERIC_SECRET: "CKK_GENERIC_SECRET",
		pkcs11.CKK_AES:            "CKK_AES",
		pkcs11.CKK_RSA:            "CKK_RSA",
		pkcs11.CKK_ECDSA:          "CKK_ECDSA",
		pkcs11.CKK_SHA256_HMAC:    "CKK_SHA256_HMAC",
		pkcs11.CKK_SHA384_HMAC:    "CKK_SHA384_HMAC",
		pkcs11.CKK_SHA512_HMAC:    "CKK_SHA512_HMAC",
		255:						   "CERTIFICATE",
	}

	// set up values for CKA_CLASS
	CKA_CLASS_MAP = map[uint]string{
		pkcs11.CKO_CERTIFICATE: "CKO_CERTIFICATE",
		pkcs11.CKO_PUBLIC_KEY:  "CKO_PUBLIC_KEY",
		pkcs11.CKO_PRIVATE_KEY: "CKO_PRIVATE_KEY",
		pkcs11.CKO_SECRET_KEY:  "CKO_SECRET_KEY",
		pkcs11.CKO_DATA:        "CKO_DATA",
	}
}

// Initialize pkcs11 context
func (p11w *Pkcs11Wrapper) InitContext() (err error) {

	// check if lib file exists
	if _, err = os.Stat(p11w.Library.Path); os.IsNotExist(err) {
		return
	}

	// try to initialize
	p11w.Context = pkcs11.New(p11w.Library.Path)
	err = p11w.Context.Initialize()
	if err != nil {
		return
	}

	// get library info
	p11w.Library.Info, err = p11w.Context.GetInfo()

	return

}

// Initialize Session to slot
func (p11w *Pkcs11Wrapper) InitSession() (err error) {

	// Look for provided slot
	slot, _, err := FindSlotByLabel(p11w.Context, p11w.SlotLabel)
	if err != nil {
		return
	}

	// Create session for matching slot
	p11w.Session, err = p11w.Context.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)

	return

}

// This will perform a login
func (p11w *Pkcs11Wrapper) Login() (err error) {

	err = p11w.Context.Login(p11w.Session, pkcs11.CKU_USER, p11w.SlotPin)

	// ignore login error CKR_USER_ALREADY_LOGGED_IN
	if err != nil && strings.Contains(err.Error(), "CKR_USER_ALREADY_LOGGED_IN") {
		err = nil
	}

	return
}

// This should return a list of object handlers and true if more than max
func (p11w *Pkcs11Wrapper) FindObjects(template []*pkcs11.Attribute, max int) (p11ObjHandlers []pkcs11.ObjectHandle, moreThanMax bool, err error) {

	// start the search for object
	err = p11w.Context.FindObjectsInit(
		p11w.Session,
		template,
	)
	if err != nil {
		return
	}

	// continue the search, get object handlers
	p11ObjHandlers, moreThanMax, err = p11w.Context.FindObjects(p11w.Session, max)
	if err != nil {
		return
	}

	// finishes the search
	err = p11w.Context.FindObjectsFinal(p11w.Session)
	if err != nil {
		return
	}

	return
}

/* Exit with message and code 1 */
func ExitWithMessage(message string, err error) {

	if err == nil {
		fmt.Printf("\nFatal Error: %s\n", message)
	} else {
		fmt.Printf("\nFatal Error: %s\n%s\n", message, err)
	}
	os.Exit(1)
}

/* returns true if substr is in string s */
func CaseInsensitiveContains(s, substr string) bool {
	s, substr = strings.ToUpper(s), strings.ToUpper(substr)
	return strings.Contains(s, substr)
}

/* Return the slotID of token label */
func FindSlotByLabel(p *pkcs11.Ctx, slotLabel string) (slot uint, index int, err error) {

	var slotFound bool

	// Get list of slots
	slots, err := p.GetSlotList(true)
	if err == nil {

		//fmt.Printf("PKCS11 provider found %d slots\n", len(slots))

		// Look for matching slot label
		for i, s := range slots {
			tInfo, errGt := p.GetTokenInfo(s)
			if errGt != nil {
				//ExitWithMessage(fmt.Sprintf("getting TokenInfo slot: %d", s), err)
				err = errGt
				return
			}
			if slotLabel == tInfo.Label {
				slotFound = true
				slot = s
				index = i
				fmt.Printf("PKCS11 provider found specified slot label: %s (slot: %d, index: %d)\n", slotLabel, slot, i)
				break
			}
		}
	}

	// set error if slot not found
	if !slotFound {
		err = errors.New(fmt.Sprintf("Could not find slot with label: %s", slotLabel))
	}

	return
}

// List content of slot
func (p11w *Pkcs11Wrapper) ListObjects(template []*pkcs11.Attribute, max int) {

	// do an object search
	objects, _, err := p11w.FindObjects(template, max)

	if err != nil {
		fmt.Println("Could not find any objects:", err)
	} else {

		// prepare table headers
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"COUNT", "CKA_CLASS", "CKA_LABEL", "CKA_ID", "CKA_KEY_TYPE", "CKA_KEY_LEN", "CKA_SUBJECT", "CKA_ISSUER"})
		table.SetCaption(true, fmt.Sprintf("Total objects found (max %d): %d", max, len(objects)))

		// populate table data
		for i, k := range objects {
			var ckaValueLen, ckaKeyType, ckaSubject, ckaIssuer []*pkcs11.Attribute
			al, err := p11w.Context.GetAttributeValue(
				p11w.Session,
				k,
				[]*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
					pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
					pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
					//pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
					//	pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
				},
			)

			if err != nil {
				panic(err)
			}
			if DecodeCKACLASS(al[2].Value[0]) == "CKO_SECRET_KEY" {
				ckaValueLen, err = p11w.Context.GetAttributeValue(
					p11w.Session,
					k,
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
					},
				)

				if err != nil {
					panic(err)
				}

			} else {
				ckaValueLen = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 0)}
			}

			if DecodeCKACLASS(al[2].Value[0]) == "CKO_CERTIFICATE" {
				ckaKeyType = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 255)}
				ckaSubject, err = p11w.Context.GetAttributeValue(
					p11w.Session,
					k,
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, nil),
					},
				)

				if err != nil {
					panic(err)
				}
				ckaIssuer, err = p11w.Context.GetAttributeValue(
					p11w.Session,
					k,
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_ISSUER, nil),
					},
				)

			} else {
				ckaKeyType, err = p11w.Context.GetAttributeValue(
					p11w.Session,
					k,
					[]*pkcs11.Attribute{
						pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
					},
				)

				if err != nil {
					panic(err)
				}
				ckaSubject = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, "NOT APPLICABLE FOR NON CKO_CERTIFICATE")}
				ckaIssuer = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ISSUER, "NOT APPLICABLE FOR NON CKO_CERTIFICATE")}
			}

			// CKA_VALUE_LEN returns an 8 byte slice, lets convert that into a uint64 (8x8 bits)
			keyLength, _ := binary.Uvarint(ckaValueLen[0].Value[0:8])
			if CaseInsensitiveContains(os.Getenv("SECURITY_P11TOOL_DEBUG"), "TRUE") {
				table.Append(
					[]string{
						fmt.Sprintf("%03d", i+1),
						DecodeCKACLASS(al[2].Value[0]),
						fmt.Sprintf("%s", al[0].Value),
						fmt.Sprintf("%x", al[1].Value),
						DecodeCKAKEY(ckaKeyType[0].Value[0]),
						fmt.Sprintf("%d", keyLength),
						fmt.Sprintf("%c", ckaSubject[0].Value),
						fmt.Sprintf("%c", ckaIssuer[0].Value),						
					},
				)
			} else {
				table.Append(
					[]string{
						fmt.Sprintf("%03d", i+1),
						DecodeCKACLASS(al[2].Value[0]),
						fmt.Sprintf("%s", al[0].Value),
						fmt.Sprintf("%x", al[1].Value),
						DecodeCKAKEY(ckaKeyType[0].Value[0]),
						fmt.Sprintf("%d", keyLength),
						fmt.Sprint(""),
						fmt.Sprint(""),
					},
				)
			}
		}

		// render table
		table.Render()

	}
}

func DecodeCKAKEY(b byte) string {

	name, present := CKA_KEY_TYPE_MAP[b]
	if present {
		return name
	} else {
		return "UNKNOWN"
	}

}

func DecodeCKACLASS(b byte) string {

	key := uint(b)
	name, present := CKA_CLASS_MAP[key]
	if present {
		return name
	} else {
		return "UNKNOWN"
	}

}

func (p11w *Pkcs11Wrapper) ImportCertificate(ec EcdsaKey) (err error) {
	
	if ec.Certificate == nil {
		err = errors.New("no cert to import")
		return
	}
	 
	//TODO calculate from key in cert
	for i, cert := range ec.Certificate {
		ec.SKI.Sha256Bytes = cert.SubjectKeyId
		if i == 0 {ec.GenSKI()}
		keyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
			pkcs11.NewAttribute(pkcs11.CKA_ISSUER, cert.RawIssuer),
			//pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.RawTBSCertificate),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.Raw),
			pkcs11.NewAttribute(pkcs11.CKA_ID, ec.SKI.Sha256Bytes),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, cert.Subject.CommonName),
		}

		_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
		if err == nil {
			fmt.Printf("Object was imported with CKA_LABEL:%s\n", cert.Subject)
		}
	
	}
	return

}

func (p11w *Pkcs11Wrapper) ImportECKey(ec EcdsaKey) (err error) {

	if ec.PrivKey == nil {
		err = errors.New("no key to import")
		return
	}

	ec.GenSKI()

	marshaledOID, err := GetECParamMarshaled(ec.PrivKey.Params().Name)
	if err != nil {
		return
	}

	// pubkey import
	ecPt := elliptic.Marshal(ec.PubKey.Curve, ec.PubKey.X, ec.PubKey.Y)
	// Add DER encoding for the CKA_EC_POINT
	ecPt = append([]byte{0x04, byte(len(ecPt))}, ecPt...)

	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),

		pkcs11.NewAttribute(pkcs11.CKA_ID, ec.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ec.keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPt),
	}

	_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
	if err != nil {
		fmt.Printf("Object FAILED TO IMPORT with CKA_LABEL:%s CKA_ID:%x\n ERROR %s", ec.keyLabel, ec.SKI.Sha256Bytes, err)
		return
	} else {
		fmt.Printf("Object was imported with CKA_LABEL:%s CKA_ID:%x\n", ec.keyLabel, ec.SKI.Sha256Bytes)
	}

	keyTemplate = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),

		pkcs11.NewAttribute(pkcs11.CKA_ID, ec.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ec.keyLabel),
		pkcs11.NewAttribute(pkcs11.CKR_ATTRIBUTE_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, ec.PrivKey.D.Bytes()),

		// implicitly enable derive for now
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
	if err != nil {
		fmt.Printf("Object FAILED TO IMPORT with CKA_LABEL:%s CKA_ID:%x\n ERROR %s", ec.keyLabel, ec.SKI.Sha256Bytes, err)
		return
	} else {
		fmt.Printf("Object was imported with CKA_LABEL:%s CKA_ID:%x\n", ec.keyLabel, ec.SKI.Sha256Bytes)
	}
	return

}

func (p11w *Pkcs11Wrapper) ImportRSAKey(rsa RsaKey) (err error) {

	if rsa.PrivKey == nil {
		err = errors.New("no key to import")
		return
	}

	rsa.GenSKI()

	// pubkey import
	pubExpBytes := big.NewInt(int64(rsa.PubKey.E)).Bytes()

	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, rsa.PubKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, pubExpBytes),

		pkcs11.NewAttribute(pkcs11.CKA_ID, rsa.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "TLSPUBKEY"),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
	}

	_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
	if err != nil {
		return
	} else {
		fmt.Printf("Object was imported with CKA_LABEL:%s CKA_ID:%x\n", "TLSPUBKEY", rsa.SKI.Sha256Bytes)
	}

	keyTemplate = []*pkcs11.Attribute{
		// According to: https://www.cryptsoft.com/pkcs11doc/v220/group__SEC__12__1__3__RSA__PRIVATE__KEY__OBJECTS.html
		// if a particular token stores values only for the CKA_PRIVATE_EXPONENT, CKA_PRIME_1, and CKA_PRIME_2 attributes,
		// then Cryptoki is certainly able to report values for all the attributes above (since they can all be computed
		// efficiently from these three values).
		// However, a Cryptoki implementation may or may not actually do this extra computation.
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, rsa.PrivKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, pubExpBytes),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, rsa.PrivKey.D.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, rsa.PrivKey.Primes[0].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, rsa.PrivKey.Primes[1].Bytes()),

		pkcs11.NewAttribute(pkcs11.CKA_ID, rsa.SKI.Sha256Bytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "TLSPRVKEY"),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),

		// Error: pkcs11: 0x12: CKR_ATTRIBUTE_TYPE_INVALID
		//pkcs11.NewAttribute(pkcs11.CKR_ATTRIBUTE_SENSITIVE, false),
	}

	_, err = p11w.Context.CreateObject(p11w.Session, keyTemplate)
	if err == nil {
		fmt.Printf("Object was imported with CKA_LABEL:%s CKA_ID:%x\n", "TLSPRVKEY", rsa.SKI.Sha256Bytes)
	}
	return

}

func (p11w *Pkcs11Wrapper) ImportECKeyFromFile(file string, keyStore string, keyStorepass string, keyLabel string) (err error) {

	// read in key from file
	//ec := EcdsaKey{}
	var ec EcdsaKey
	

	//err = ec.ImportPrivKeyFromFile(file)
	switch keyStore {
		case "p12":
			ec = EcdsaKey{}
			ec.keyLabel = keyLabel
			err = ec.ImportPrivKeyFromP12(file, keyStorepass)
			if err != nil {
			return err
			}
		default:
			ec = EcdsaKey{}
			ec.keyLabel = keyLabel
			err = ec.ImportPrivKeyFromFile(file)
			if err != nil {
				return err
			}
		}

	// import key to hsm
	err = p11w.ImportECKey(ec)
	if len(ec.Certificate) != 0 {
		err = p11w.ImportCertificate(ec)
	}

	return

}

func (p11w *Pkcs11Wrapper) ImportRSAKeyFromFile(file string, keyStore string) (err error) {

	// read in key from file
	rsa := RsaKey{}
	err = rsa.ImportPrivKeyFromFile(file)
	if err != nil {
		return
	}

	// import key to hsm
	err = p11w.ImportRSAKey(rsa)

	return

}

func (p11w *Pkcs11Wrapper) findKeyPairFromSKI(ski []byte, keyType bool) (*pkcs11.ObjectHandle, error) {
	ktype := pkcs11.CKO_PUBLIC_KEY
	if keyType == privateKeyFlag {
		ktype = pkcs11.CKO_PRIVATE_KEY
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ktype),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
	}
	if err := p11w.Context.FindObjectsInit(p11w.Session, template); err != nil {
		return nil, err
	}

	// single session instance, assume one hit only
	objs, _, err := p11w.Context.FindObjects(p11w.Session, 1)
	if err != nil {
		return nil, err
	}
	if err = p11w.Context.FindObjectsFinal(p11w.Session); err != nil {
		return nil, err
	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("Key not found [%s]", hex.Dump(ski))
	}

	return &objs[0], nil
}

func (p11w *Pkcs11Wrapper) signP11ECDSA(ski SubjectKeyIdentifier, msg []byte) (R, S *big.Int, err error) {

	privateKey, err := p11w.findKeyPairFromSKI(ski.Sha256Bytes, privateKeyFlag)
	if err != nil {
		return nil, nil, fmt.Errorf("Private key not found [%s]\n", err)
	}

	err = p11w.Context.SignInit(p11w.Session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, *privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Sign-initialize  failed [%s]\n", err)
	}

	var sig []byte

	sig, err = p11w.Context.Sign(p11w.Session, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: sign failed [%s]\n", err)
	}

	R = new(big.Int)
	S = new(big.Int)
	R.SetBytes(sig[0 : len(sig)/2])
	S.SetBytes(sig[len(sig)/2:])

	return R, S, nil
}

func (p11w *Pkcs11Wrapper) signECDSA(k EcdsaKey, digest []byte) (signature []byte, err error) {
	r, s, err := p11w.signP11ECDSA(k.SKI, digest)
	if err != nil {
		return nil, err
	}

	s, _, err = utils.ToLowS(k.PubKey, s)
	if err != nil {
		return nil, err
	}

	return utils.MarshalECDSASignature(r, s)
}

func (p11w *Pkcs11Wrapper) Sign(k Key, digest []byte) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	// Check key type
	switch k.(type) {
	case *EcdsaKey:
		return p11w.signECDSA(*k.(*EcdsaKey), digest)
	default:
		return p11w.signECDSA(*k.(*EcdsaKey), digest)
	}
}

//TODO implement Public() for crypto.signer

func (p11w *Pkcs11Wrapper) Public() {
	return
}

/*TODO Implement CSR Request to call csr.Generate with EC Key from HSM with SKI implementing crypto.signer from Pkcs11Wrapper Struct
	var req = &CertificateRequest{
		Names: []Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:         "cloudflare.com",
		Hosts:      []string{"cloudflare.com", "www.cloudflare.com", "192.168.0.1", "jdoe@example.com"},
		KeyRequest: &BasicP11Request{"ecdsa", 256},
	}


func (p11r *BasicP11Request) Generate() (crypto.PrivateKey, error) {
	//FAKE the Generate and return a handle to a previously created private key
	return
}

func (p11r *BasicP11Request) SigAlgo() x509.SignatureAlgorithm {
	return
}
func (p11r *BasicP11Request) Algo() string {
	return p11r.A
}

// Size returns the requested key size.
func (p11r *BasicP11Request) Size() int {
	return p11r.S
}
*/

func (p11w *Pkcs11Wrapper) SignMessage(message string, key pkcs11.ObjectHandle) (signature string, err error) {

	// TODO: diff mech needed for rsa. example: CKM_RSA_PKCS CKM_ECDSA
	err = p11w.Context.SignInit(p11w.Session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, key)
	if err != nil {
		return
	}

	// Test signing with mechanism CKM_ECDSA
	// Hash message first
	// TODO: make this hash dynamic corresponding to key size
	d := sha256.Sum256([]byte(message))
	digest := d[:]
	signatureBytes, err := p11w.Context.Sign(p11w.Session, digest)
	if err != nil {
		return
	}

	signature = hex.EncodeToString(signatureBytes)

	return
}

/* Advanced form of signing message, specify mechanism. Assume data is already prepared for mechanism (not altered in this function) */
func (p11w *Pkcs11Wrapper) SignMessageAdvanced(data []byte, key pkcs11.ObjectHandle, mechanism *pkcs11.Mechanism) (signature string, err error) {

	err = p11w.Context.SignInit(p11w.Session, []*pkcs11.Mechanism{mechanism}, key)
	if err != nil {
		return
	}

	signatureBytes, err := p11w.Context.Sign(p11w.Session, data)
	if err != nil {
		return
	}

	signature = hex.EncodeToString(signatureBytes)

	return
}

func (p11w *Pkcs11Wrapper) VerifySignature(message string, signature string, key pkcs11.ObjectHandle) (verified bool, err error) {

	err = p11w.Context.VerifyInit(p11w.Session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, key)
	if err != nil {
		return
	}

	// Test signing with mechanism CKM_ECDSA
	// Hash message first
	// TODO: make this hash dynamic corresponding to key size
	d := sha256.Sum256([]byte(message))
	digest := d[:]

	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		return
	}

	// if there is an error, we can assume signature was invalid:
	// Error: pkcs11: 0xC0: CKR_SIGNATURE_INVALID
	errSig := p11w.Context.Verify(p11w.Session, digest, signatureBytes)
	if errSig == nil {
		verified = true
	}

	return
}
