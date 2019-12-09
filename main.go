package main

import (
	"encoding/hex" //"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strings" //"github.com/cloudflare/cfssl/csr"
	//"github.com/cloudflare/cfssl/log"
	"github.com/miekg/pkcs11"
	pw "github.com/scottallan/p11tool-new/pkcs11wrapper"
	"golang.org/x/crypto/ssh/terminal"
	"os/signal"
	"syscall"
	"time"
)

const (

	// locations to search for pkcs11 lib if none are specified
	defaultLibPaths = `
/usr/lib/softhsm/libsofthsm2.so,
/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so,
/usr/lib/s390x-linux-gnu/softhsm/libsofthsm2.so,
/usr/lib/powerpc64le-linux-gnu/softhsm/libsofthsm2.so,
/usr/local/Cellar/softhsm/2.1.0/lib/softhsm/libsofthsm2.so,
/usr/local/lib/softhsm/libsofthsm2.so`
)

var (
	// shared pkcs11 wrapper struct
	p11w pw.Pkcs11Wrapper
)

// exit cleanly when error is no nil
func exitWhenError(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

type termInfo struct {
	termState *terminal.State
	curState  *terminal.State
}

// search comma-separated list of paths for pkcs11 lib
func searchForLib(paths string) (firstFound string, err error) {

	libPaths := strings.Split(paths, ",")
	for _, path := range libPaths {
		if _, err = os.Stat(strings.TrimSpace(path)); !os.IsNotExist(err) {
			firstFound = strings.TrimSpace(path)
			break
		}
	}

	if firstFound == "" {
		err = fmt.Errorf("no suitable paths for pkcs11 library found: %s", paths)
	}

	return
}

func (t *termInfo) askForPin(less bool) (slotPin string, err error) {
	//Start Fun Message for Security.  Note we dont do any of this and simply use terminal package to read in password
	if !less {
		fmt.Printf("***High Security Password Mode Detected***\n\n***Preparing SecureRandom Encrypted Memory Space***\n")
		for i := 1; i <= 10; i++ {
			if math.Mod(float64(i), 2) == 1 {
				fmt.Printf(". %d%%", i*10)
			} else {
				fmt.Print("...")
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	fmt.Printf("\nEnter Token Password (Pin):")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))

	if err != nil {
		fmt.Println("Error Getting PIN from Terminal", err)
		return
	}
	slotPin = string(bytePassword)
	bytePassword = []byte{}
	fmt.Println() // it's necessary to add a new line after user's input
	return
}

func (t *termInfo) cleanupPin(slotPin string, p11Pin *string, less bool) {
	if slotPin == "" {
		if !less {
			//Output Fun message for Security.  Note we dont do this scrubbing and simply blank the password before exiting
			fmt.Printf("\n\n*********Srubbing Encrypted Memory Space for Secure Pin*********\n\n*********Writing Random 0's and 1's across 1,000,000 loops to Encrypted Memory Location!!!*********\n\nCLEANING:")
			for i := 1; i <= 10; i++ {
				if math.Mod(float64(i), 2) == 1 {
					fmt.Printf("... %d writes complete...", i*100000)
				} else {
					fmt.Print("...")
				}
				time.Sleep(500 * time.Millisecond)
				if i == 10 {
					fmt.Println("1,000,000 writes complete... EXITING\n")
				}
			}
		}
	}
	*p11Pin = ""
}

/*CaseInsensitiveContains Returns true if substr is in string s */
func CaseInsensitiveContains(s, substr string) bool {
	s, substr = strings.ToUpper(s), strings.ToUpper(substr)
	return strings.Contains(s, substr)
}

func main() {

	// get flags
	pkcs11Library := flag.String("lib", "", "Location of pkcs11 library")
	slotLabel := flag.String("slot", "ForFabric", "Slot Label")
	slotPin := flag.String("pin", "", "Slot PIN")
	action := flag.String("action", "list", "list,import,generate,generateAndImport,generateSecret,generateAES,generateDES,wrapKeyWithDES3,unwrapASYMWithDES3,getSKI,getSkiFromCert,getSkiFromB64Cert,SignHMAC384,TestAESGCM,generateCSR,importCert,deleteObj")
	keyFile := flag.String("keyFile", "/some/dir/key.pem)", "path to key you want to import or getSKI")
	keyType := flag.String("keyType", "EC", "Type of key (EC,RSA,GENERIC_SECRET,AES,SHA256_HMAC,SHA384_HMAC,DES3)")
	keyLen := flag.Int("keyLen", 32, "Key Length for CKK_GENERIC_SECRET (32,48,...)")
	keyLabel := flag.String("keyLabel", "tmpkey", "Label of CKK_GENERIC_SECRET")
	keyStore := flag.String("keyStore", "file", "Keystore Type (file,pkcs12)")
	keyStorepass := flag.String("keyStorepass", "securekey", "Keystore Storepass")
	key := flag.String("key", "", "Key as HEX String")
	csrInfo := flag.String("csrInfo", "", "json file with values for CSR Creation")
	wrapKey := flag.String("wrapKey", "wrapKey", "DES3 Wrapping Key for unwrapping key material onto Gemalto")
	objClass := flag.String("objClass", "", "CKA_CLASS for Deletion of Objects")
	outF := flag.String("outFile", "out.pem", "output file for CSR Generation")
	noDec := flag.Bool("noDec", false, "when set wrapped material will remain encrypted")
	less := flag.Bool("less", true, "Dont show password preamble")

	byCKAID := flag.Bool("byCKAID", false, "when set we will assume keyLabel is a CKA_ID represented as a string")

	mechOver := flag.String("mechanismOverride", "", "Allow override of mechanism - only supported on certain operations [wrapKeyWithDES3, wrapKeyWithAES]")

	maxObjectsToList := flag.Int("maxObjectsToList", 50, "Paramter to be used with -action list to specify how many objects to print")

	var gracefulStop = make(chan os.Signal)
	signal.Notify(gracefulStop, syscall.SIGTERM)
	signal.Notify(gracefulStop, syscall.SIGINT)

	flag.Parse()

	var err error
	//Neet to Get State of the Existing Terminal
	termState := termInfo{}
	tState, err := terminal.GetState(int(syscall.Stdin))
	termState.termState = tState
	go func() {
		sig := <-gracefulStop
		var err error
		fmt.Printf("\n**********caught signal: %+v  EXITING\n", sig)
		cState, err := terminal.GetState(int(syscall.Stdin))
		if err != nil {
			panic(err)
		}
		termState.curState = cState
		if termState.curState == termState.termState {
			fmt.Println("Terminal State OK!  Exiting Normally")
			panic(err)
		} else {
			fmt.Printf("Terminal State Changed!\n[Current State: %v]\n[Original State :%v] Reverting before Exiting\n", *termState.curState, *termState.termState)
			err = terminal.Restore(int(syscall.Stdin), termState.termState)
			panic(err)
		}
	}()

	// complete actions which do not require HSM
	switch *action {

	case "getSKI":
		if *keyType == "RSA" {
			key := pw.RsaKey{}
			err = key.ImportPrivKeyFromFile(*keyFile)
			exitWhenError(err)
			key.GenSKI()
			fmt.Printf("SKI(sha256): %s\n", key.SKI.Sha256)
			os.Exit(0)
		} else {
			key := pw.EcdsaKey{}
			err = key.ImportPrivKeyFromFile(*keyFile)
			exitWhenError(err)
			key.GenSKI()
			fmt.Printf("SKI(sha256): %s\n", key.SKI.Sha256)
			os.Exit(0)
		}

	case "getSkiFromCert":
		key := pw.EcdsaKey{}
		err = key.ImportPubKeyFromCertFile(*keyFile)
		exitWhenError(err)
		key.GenSKI()
		fmt.Printf("SKI(sha256): %s\n", key.SKI.Sha256)
		os.Exit(0)

	case "getSkiFromB64Cert":
		key := pw.EcdsaKey{}
		err = key.ImportPubKeyFromBase64Cert(*keyFile)
		exitWhenError(err)
		key.GenSKI()
		fmt.Printf("SKI(sha256): %s\n", key.SKI.Sha256)
		os.Exit(0)

	}

	// complete actions which require HSM

	// initialize pkcs11
	var p11Lib string
	var p11Pin string

	if *pkcs11Library == "" {
		p11Lib, err = searchForLib(defaultLibPaths)
		exitWhenError(err)
	} else {
		p11Lib, err = searchForLib(*pkcs11Library)
		exitWhenError(err)
	}
	if *slotPin == "" {
		p11Pin, err = termState.askForPin(*less)
		if err != nil {
			exitWhenError(err)
		}
	} else {
		p11Pin = *slotPin
	}

	p11w = pw.Pkcs11Wrapper{
		Library: pw.Pkcs11Library{
			Path: p11Lib,
		},
		SlotLabel: *slotLabel,
		SlotPin:   p11Pin,
	}

	err = p11w.InitContext()
	exitWhenError(err)

	err = p11w.InitSession()
	exitWhenError(err)

	err = p11w.Login()
	exitWhenError(err)

	// defer cleanup
	defer p11w.Context.Destroy()
	defer p11w.Context.Finalize()
	defer p11w.Context.CloseSession(p11w.Session)
	defer p11w.Context.Logout(p11w.Session)
	defer termState.cleanupPin(*slotPin, &p11Pin, *less)

	switch *action {

	case "import":
		if *keyType == "RSA" {
			err = p11w.ImportRSAKeyFromFile(*keyFile, *keyStore)
			exitWhenError(err)
		} else if *keyType == "AES" ||
			*keyType == "GENERIC_SECRET" ||
			*keyType == "SHA256_HMAC" ||
			*keyType == "SHA384_HMAC" {
			err = p11w.ImportSymKey(*keyType, *key, *keyStore, *keyStorepass, *keyLabel)
			exitWhenError(err)
		} else {
			err = p11w.ImportECKeyFromFile(*keyFile, *keyStore, *keyStorepass, *keyLabel)
			exitWhenError(err)
		}

	case "importCert":
		ec := pw.EcdsaKey{}
		c := pw.GetCert(*keyFile)
		ec.Certificate = c
		ec.SKI.Sha256 = *keyLabel
		Sha256Bytes, err := hex.DecodeString(ec.SKI.Sha256)
		exitWhenError(err)
		ec.SKI.Sha256Bytes = Sha256Bytes
		err = p11w.ImportCertificate(ec)
		exitWhenError(err)

	case "generate":
		if *keyType == "RSA" {
			rsa := pw.RsaKey{}
			err := p11w.GenerateRSA(rsa, *keyLen, *keyLabel)
			exitWhenError(err)
		} else if *keyType == "EC" {
			ec := pw.EcdsaKey{}
			//TODO pass in from argument
			ec.NamedCurveAsString = "P-256"
			_, err := p11w.GenerateEC(ec)
			exitWhenError(err)
		}

	case "deleteObj":
		if *objClass == "ALL" {
			p11w.DeleteObj("ALL", "")
		} else {
			p11w.DeleteObj(*objClass, *keyLabel)
		}

	case "generateCSR":

		if *keyType == "RSA" {
			//rsa := pw.RsaKey{}
			//_, _, err = p11w.GenCSR(rsa)
			//TODO generate and sign RSA

		} else if *keyType == "EC" {
			ec := pw.EcdsaKey{}
			ec.SKI.Sha256 = *keyLabel

			csrInfo := ec.GetCSRInfo(*csrInfo)
			/*ec.Req = &pw.CSRInfo{
				Names: []pw.Name{names},
				Hosts: hosts.Hosts,
			}*/
			ec.Req = &csrInfo

			fmt.Println(pw.ToJson(csrInfo))

			csr, _, err := p11w.GenCSR(ec)
			exitWhenError(err)
			outFile, err := os.Create(*outF)
			if err != nil {
				fmt.Printf("Unable to write CSR %s", err.Error())
				return
			}
			defer outFile.Close()
			fmt.Printf("writing csr to %s\n", *outF)
			err = ioutil.WriteFile(*outF, csr, 0644)
			if err != nil {
				return
			}
		}

	case "generateAndImport":
		if *keyType == "RSA" {
			rsa := pw.RsaKey{}
			rsa.Generate(2048)
			p11w.ImportRSAKey(rsa)
		} else {
			ec := pw.EcdsaKey{}
			// TODO: fix non working curves (P-521)
			ec.Generate("P-256")
			p11w.ImportECKey(ec)
		}

	case "SignHMAC384":
		pkcs11_attr := pkcs11.NewAttribute(pkcs11.CKA_LABEL, *keyLabel)
		p11w.ListObjects(
			[]*pkcs11.Attribute{
				pkcs11_attr,
			}, *maxObjectsToList,
		)
		o, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *keyLabel),
		},
			1,
		)
		exitWhenError(err)
		testMsg := []byte("someRandomString")
		hmac, err := p11w.SignHmacSha384(o[0], testMsg)
		exitWhenError(err)
		fmt.Printf("successfully tested CKM_SHA384_HMAC on key with LABEL: %s\n HMAC %x\n", *keyLabel, hmac)

	case "unwrapASYMWithDES3":
		w, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *wrapKey),
		},
			1,
		)
		exitWhenError(err)

		switch *keyType {
		case "EC":
			err := p11w.UnWrapECKeyFromFile(*keyFile, *keyStore, *keyStorepass, *keyLabel, w[0])
			exitWhenError(err)
		case "RSA":
			err := p11w.UnWrapRSAKeyFromFile(*keyFile, *keyStore, *keyStorepass, *keyLabel, w[0])
			exitWhenError(err)
		case "AES":
		   wrappedKey, err := p11w.WrapSymKey("AES", *key, *keyLen, w[0])
		   if err != nil {
			   fmt.Printf("Unable to Wrap key: %v\n", *key)
		   }
		   fmt.Printf("Wrapped Key to Value: %v\n", wrappedKey)
		   //Unwrap key onto HSM
		   err = p11w.UnwrapSymKey("AES", wrappedKey, w[0], *keyLabel)
		   exitWhenError(err)
		}

	case "wrapKeyWithDES3":
		w, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *wrapKey),
		},
			1,
		)
		exitWhenError(err)

		var wrappedKey []byte
		switch *keyType {
		case "RSA":
			wrappedKey, err = p11w.WrapP11Key("DES3", *objClass, *keyLabel, w[0], *byCKAID, *mechOver)
			exitWhenError(err)
			decryptedKey, err := p11w.DecryptP11Key("DES3", wrappedKey, w[0], *mechOver)
			outFile, err := os.Create(*outF)
			if err != nil {
				fmt.Printf("Unable to write key %s", err.Error())
				return
			}
			defer outFile.Close()

			fmt.Printf("writing key to %s\n", *outF)
			if *noDec {
				fmt.Printf("writing encrypted\n?")
				err = ioutil.WriteFile(*outF, wrappedKey, 0644)
			} else {
				fmt.Printf("writing decrypted\n")
				err = ioutil.WriteFile(*outF, decryptedKey, 0644)
			}

			if err != nil {
				return
			}
		case "EC":
			fmt.Printf("Need to Implement EC Key Wrapping")

		}
	
	case "wrapKeyWithAES":
		w, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *wrapKey),
		},
			1,
		)
		exitWhenError(err)

		var wrappedKey []byte
		switch *keyType {
		case "RSA":
			wrappedKey, err = p11w.WrapP11Key("AES", *objClass, *keyLabel, w[0], *byCKAID, *mechOver)
			exitWhenError(err)
			decryptedKey, err := p11w.DecryptP11Key("AES", wrappedKey, w[0], *mechOver)
			outFile, err := os.Create(*outF)
			if err != nil {
				fmt.Printf("Unable to write key %s", err.Error())
				return
			}
			defer outFile.Close()

			fmt.Printf("writing key to %s\n", *outF)
			if *noDec {
				fmt.Printf("writing encrypted\n?")
				err = ioutil.WriteFile(*outF, wrappedKey, 0644)
			} else {
				fmt.Printf("writing decrypted\n")
				err = ioutil.WriteFile(*outF, decryptedKey, 0644)
			}

			if err != nil {
				return
			}
		case "EC":
			fmt.Printf("Need to Implement EC Key Wrapping")

		}

	case "TestAESGCM":
		pkcs11Attr := pkcs11.NewAttribute(pkcs11.CKA_LABEL, *keyLabel)
		p11w.ListObjects(
			[]*pkcs11.Attribute{
				pkcs11Attr,
			}, *maxObjectsToList,
		)
		o, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *keyLabel),
		},
			1,
		)
		exitWhenError(err)
		testMsg := []byte("ThisIsATestClearTextString")
		enc, iv, err := p11w.EncAESGCM(o[0], testMsg)
		exitWhenError(err)
		fmt.Printf("successfully encrypted  message '%s' with CKM_AES_GCM and key with LABEL: %s\n CipherText %v\n IV: %v\n", testMsg, *keyLabel, enc, iv)
		dec, err := p11w.DecAESGCM(o[0], enc, iv)
		exitWhenError(err)
		fmt.Printf("successfully decrypted ciptherText '%v' with CKM_AES_GCM and key with LABEL: %s\n ClearText %s\n", enc, *keyLabel, dec)

	case "generateSecret":
		if *keyType == "GENERIC_SECRET" || *keyType == "SHA256_HMAC" || *keyType == "SHA384_HMAC" {
			//Generate Key
			symKey, err := p11w.CreateSymKey(*keyLabel, *keyLen, *keyType)
			exitWhenError(err)
			testMsg := []byte("someRandomString")
			hmac, err := p11w.SignHmacSha384(symKey, testMsg)
			exitWhenError(err)
			fmt.Printf("Successfully tested CKM_SHA384_HMAC on key with label: %s \n HMAC %x\n", *keyLabel, hmac)
			p11w.ListObjects(
				[]*pkcs11.Attribute{},
				*maxObjectsToList,
			)

		}

	case "generateAES":
		if *keyType == "AES" {
			//Generate Key
			_, err := p11w.CreateSymKey(*keyLabel, *keyLen, *keyType)
			exitWhenError(err)
			p11w.ListObjects(
				[]*pkcs11.Attribute{},
				*maxObjectsToList,
			)

		}

	case "generateDES":
		if *keyType == "DES3" {
			//Generate DES Key
			_, err := p11w.CreateSymKey(*keyLabel, *keyLen, *keyType)
			exitWhenError(err)
		}

	case "testEc":

		message := "Some Test Message"

		// test SW ecdsa sign and verify
		ec := pw.EcdsaKey{}
		ec.ImportPrivKeyFromFile("contrib/testfiles/key.pem")
		sig, err := ec.SignMessage(message)
		exitWhenError(err)
		fmt.Println("Signature:", sig)
		verified := ec.VerifySignature(message, sig)
		fmt.Println("Verified:", verified)

		// test PKCS11 ecdsa sign and verify
		// Find object
		id, err := hex.DecodeString("018f389d200e48536367f05b99122f355ba33572009bd2b8b521cdbbb717a5b5")
		exitWhenError(err)

		o, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "BCPRV1"),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		},
			2,
		)

		exitWhenError(err)

		sig, err = p11w.SignMessage(message, o[0])
		exitWhenError(err)
		fmt.Println("pkcs11 Signature:", sig)
		verified = ec.VerifySignature(message, sig)
		fmt.Println("Verified:", verified)

		// test pkcs11 verify
		o, _, err = p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "BCPUB1"),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		},
			2,
		)

		verified, err = p11w.VerifySignature(message, sig, o[0])
		exitWhenError(err)
		fmt.Println("pkcs11 Verified:", verified)

		// derive test
		ec2 := pw.EcdsaKey{}
		ec2.Generate("P-256")

		secret, err := ec.DeriveSharedSecret(ec2.PubKey)
		exitWhenError(err)
		fmt.Printf("shared secret: %x\n", secret)

		secret, err = ec2.DeriveSharedSecret(ec.PubKey)
		exitWhenError(err)
		fmt.Printf("shared secret: %x\n", secret)

	case "testRsa":
		message := "Some Test Message"

		rsa := pw.RsaKey{}
		//rsa.Generate(2048)
		err = rsa.ImportPrivKeyFromFile("contrib/testfiles/key.rsa.pem")
		exitWhenError(err)
		rsa.GenSKI()

		err = p11w.ImportRSAKey(rsa)
		exitWhenError(err)

		sig, err := rsa.SignMessage(message, 256)
		exitWhenError(err)

		fmt.Println("Signature:", sig)

		// test PKCS11 ecdsa sign and verify
		// Find object
		id, err := hex.DecodeString("0344ae0121e025d998f5923174e9e4d69b899144ac79bfdf01c065bd4d99d6cb")
		exitWhenError(err)

		o, _, err := p11w.FindObjects([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "TLSPRVKEY"),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		},
			2,
		)
		exitWhenError(err)

		sig, err = p11w.SignMessageAdvanced([]byte(message), o[0], pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil))
		exitWhenError(err)

		fmt.Println("pkcs11 Signature:", sig)

	default:
		p11w.ListObjects(
			[]*pkcs11.Attribute{},
			*maxObjectsToList,
		)

	}

}
