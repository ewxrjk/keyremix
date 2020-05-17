package keyremix

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/pem"
	"log"
	"math/big"
	"math/rand"

	"golang.org/x/crypto/ssh"
)

// OpenSSH the tool has used a variety of formats over time,
// reflecting the three formats supported by keyremix.
//
// 1) "ssh1". Only RSA is supported ("rsa1" in ssh-keygen).
//    See ssh1.go.
//
// 2) "ssh2". The actual format depends on the key type.
// 2a) PKCS#1 DER/PEM format, for RSA keys.
// 2b) PKCS#8 DER/PEM format, for ECDSA keys.
// 2c) OpenSSL's "traditional" DER/PEM format for DSA keys.
//    If this is specified anywhere more formal that than the OpenSSL source code
//    then I have no been able to find it.
//    You can request this explicitly with -T format=openssl.
//    Public keys are: TYPE BASE64 COMMENT
//    where BASE64 is the base64 encoding of the SSH wire format for the public key.
//
// 3) "openssh". OpenSSL's own private PEM format.
//    See PROTOCOL.key from the OpenSSH source code.
//    Public keys match "ssh2".

// opensshKeyFile is a OpenSSH-format container for private keys
type opensshKeyFile struct {
	Ciphername string
	Kdfname    string
	Kdfoptions string
	Keys       uint32
	PublicKey  string
	PrivateKey string
}

type opensshCheck struct {
	Checkint1 uint32
	Checkint2 uint32
}

type opensshPrivateKey struct {
	Key     crypto.PrivateKey
	Comment string
}

type opensshCipher struct {
	BlockSize int
}

var opensshCiphers = map[string]opensshCipher{
	"none": {
		BlockSize: 8,
	},
}

func (s *opensshKeyFile) Marshal() (output []byte) {
	// PROTOCOL.key doesn't tell you about the trailing 0.
	output = append([]byte("openssh-key-v1\x00"), ssh.Marshal(s)...)
	return
}

// SetKeys sets the key in the container.
//
// Like OpenSSH we only supports len(keys)==1.
func (s *opensshKeyFile) SetKeys(keys []opensshPrivateKey, password string) (err error) {
	if password != "" {
		err = ErrNotImplemented
		return
	}
	if len(keys) != 1 {
		err = ErrNotImplemented
		return
	}
	if password == "" {
		s.Ciphername = "none"
		s.Kdfname = "none"
		s.Kdfoptions = ""
	}
	s.Keys = uint32(len(keys))
	check := opensshCheck{}
	check.Checkint1 = rand.Uint32()
	check.Checkint2 = check.Checkint1
	k := keys[0]
	var pubkey interface{}
	if pubkey, err = GetPublicKey(k.Key); err != nil {
		return
	}
	var b []byte
	if b, err = sshMarshalKey(pubkey); err != nil {
		return
	}
	s.PublicKey = string(b)
	if b, err = sshMarshalKey(k.Key); err != nil {
		return
	}
	// ssh.Marshal only really knows about structs
	comment := ssh.Marshal(struct{ V string }{k.Comment})
	plaintext := ssh.Marshal(check)
	plaintext = append(plaintext, b...)
	plaintext = append(plaintext, comment...)
	blocksize := opensshCiphers[s.Ciphername].BlockSize
	paddingbyte := uint8(1)
	for len(plaintext)%blocksize != 0 {
		plaintext = append(plaintext, paddingbyte)
		paddingbyte++
	}
	// TODO encrypt, if a password
	s.PrivateKey = string(plaintext)
	return
}

// serializeOpenSSH converts a private key to OpenSSH format.
func serializeOpenSSH(key interface{}, password string, comment string) (output []byte, err error) {
	skf := opensshKeyFile{}
	if err = skf.SetKeys([]opensshPrivateKey{{key, comment}}, password); err != nil {
		return
	}
	skfbytes := skf.Marshal()
	b := &pem.Block{
		Type:    opensshPemType,
		Headers: nil,
		Bytes:   skfbytes,
	}
	/*
		fmt.Printf("%T:\n", key)
		for i := 0; i < len(skfbytes); i += 16 {
			fmt.Printf("%08x ", i)
			for j := 0; j < 16 && i+j < len(skfbytes); j++ {
				fmt.Printf(" %02x", skfbytes[i+j])
				if j == 7 {
					fmt.Printf(" ")
				}
			}
			fmt.Printf("  |")
			for j := 0; j < 16 && i+j < len(skfbytes); j++ {
				ch := skfbytes[i+j]
				if ch < 32 || ch > 126 {
					ch = '.'
				}
				fmt.Printf("%c", ch)
			}
			fmt.Printf("|\n")
		}
	*/
	output = pem.EncodeToMemory(b)
	return
}

type sshRSAPrivateKey struct {
	Type string
	N    string
	E    string
	D    string
	Iqmp string
	P    string
	Q    string
}

type sshRSAPublicKey struct {
	Type string
	N    string
	E    string
}

type sshDSAPrivateKey struct {
	Type string
	P    string
	Q    string
	G    string
	Y    string
	X    string
}

type sshDSAPublicKey struct {
	Type string
	P    string
	Q    string
	G    string
	Y    string
}

type sshECDSAPrivateKey struct {
	Type  string
	Curve string
	Q     []byte
	D     string
}

type sshECDSAPublicKey struct {
	Type  string
	Curve string
	Q     []byte
}

type sshED25519PrivateKey struct {
	Type string
	A    string
	K    string
}

type sshED25519PublicKey struct {
	Type string
	A    string
}

// sshConvertKey converts a key from Go format to SSH format
func sshConvertKey(key interface{}) (sshkey interface{}, err error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		sshkey = sshRSAPrivateKey{
			Type: "ssh-rsa",
			N:    sshConvertInt(k.N),
			E:    sshConvertInt(big.NewInt(int64(k.E))),
			D:    sshConvertInt(k.D),
			Iqmp: sshConvertInt(k.Precomputed.Qinv),
			P:    sshConvertInt(k.Primes[0]),
			Q:    sshConvertInt(k.Primes[1]),
		}
	case *rsa.PublicKey:
		sshkey = sshRSAPublicKey{
			Type: "ssh-rsa",
			N:    sshConvertInt(k.N),
			E:    sshConvertInt(big.NewInt(int64(k.E))),
		}
	case *dsa.PrivateKey:
		sshkey = sshDSAPrivateKey{
			Type: "ssh-dss",
			P:    sshConvertInt(k.P),
			Q:    sshConvertInt(k.Q),
			G:    sshConvertInt(k.G),
			Y:    sshConvertInt(k.Y),
			X:    sshConvertInt(k.X),
		}
	case *dsa.PublicKey:
		sshkey = sshDSAPublicKey{
			Type: "ssh-dss",
			P:    sshConvertInt(k.P),
			Q:    sshConvertInt(k.Q),
			G:    sshConvertInt(k.G),
			Y:    sshConvertInt(k.Y),
		}
	case *ecdsa.PrivateKey:
		curve := sshCurveName(k.Params())
		sshkey = sshECDSAPrivateKey{
			Type:  "ecdsa-sha2-" + curve,
			Curve: curve,
			Q:     elliptic.Marshal(k.Curve, k.X, k.Y),
			D:     sshConvertInt(k.D),
		}
	case *ecdsa.PublicKey:
		curve := k.Params().Name
		sshkey = sshECDSAPublicKey{
			Type:  "ecdsa-sha2-" + curve,
			Curve: curve,
			Q:     elliptic.Marshal(k.Curve, k.X, k.Y),
		}
	case ed25519.PrivateKey:
		sshkey = sshED25519PrivateKey{
			Type: "ssh-ed25519",
			A:    string(k[ed25519.PrivateKeySize:]),
			K:    string(k[:ed25519.PrivateKeySize]),
		}
	case ed25519.PublicKey:
		sshkey = sshED25519PublicKey{
			Type: "ssh-ed25519",
			A:    string(k),
		}
	default:
		err = ErrNotImplemented
	}
	return
}

// sshMarshalKey marshals a Go key in SSH format
func sshMarshalKey(key interface{}) (output []byte, err error) {
	var k interface{}
	if k, err = sshConvertKey(key); err != nil {
		return
	}
	output = ssh.Marshal(k)
	return
}

// sshConvertInt converts a Go bignum to a SSH format bignum
func sshConvertInt(n *big.Int) (output string) {
	b := n.Bytes()
	if len(b) > 0 && b[0] > 127 {
		b = append([]byte{0}, b...)
	}
	return string(b)
}

// sshCurveName returns the SSH name for an ECC domain
func sshCurveName(params *elliptic.CurveParams) (name string) {
	switch params.Name {
	case "P-256":
		name = "nistp256"
	case "P-384":
		name = "nistp384"
	case "P-521":
		name = "nistp521"
	default:
		log.Panicf("unrecognized ECC domain %s", params.Name)
	}
	return
}

// ssh2SerializePublicKey serializes a public key in SSH2 format
func ssh2SerializePublicKey(key crypto.PublicKey, comment string) (output []byte, err error) {
	var pubkey ssh.PublicKey
	if pubkey, err = ssh.NewPublicKey(key); err != nil {
		return
	}
	output = ssh.MarshalAuthorizedKey(pubkey)
	output = output[:len(output)-1]
	output = append(output, ' ')
	output = append(output, []byte(comment)...)
	output = append(output, '\n')
	return
}
