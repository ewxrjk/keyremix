package keyremix

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"

	"bytes"

	"github.com/golang/go/src/log"
	"golang.org/x/crypto/ssh"
)

const opensshPemType = "OPENSSH PRIVATE KEY"

// SSHFormat is an SSH key format
type SSHFormat int

const (
	// SSHFormat1 is the (very obsolete) SSH1 format
	SSHFormat1 SSHFormat = iota

	// SSHFormat2 is OpenSSH up to 6.4
	SSHFormat2

	// SSHFormatOpenSSH is OpenSSH from 6.5
	SSHFormatOpenSSH
)

// ErrUnknownKeyFormat is returned for unrecognized key formats
var ErrUnknownKeyFormat = errors.New("unknown key format")

// Serialize converts a key to this format.
//
// args is a collection of format-dependent parameters.
func (sf SSHFormat) Serialize(key interface{}, args map[string]string) (output []byte, err error) {
	var password string
	var ok bool
	if password, ok = args["password"]; ok {
		err = ErrNotImplemented
		return
	}
	var comment string
	if comment, ok = args["comment"]; !ok {
		comment = "unknown@unknown"
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		switch sf {
		case SSHFormatOpenSSH:
			output, err = serializeOpenSSH(key, password, comment)
			return
		case SSHFormat1:
			output, err = ssh1SerializePrivateKey(k, password, comment)
			return
		case SSHFormat2:
			output, err = Pkcs1Pem.Serialize(k, args)
			return
		default:
			err = ErrUnknownKeyFormat
			return
		}
	case *dsa.PrivateKey:
		switch sf {
		case SSHFormatOpenSSH:
			output, err = serializeOpenSSH(key, password, comment)
			return
		case SSHFormat2:
			output, err = MarshalOpenSSLDSAKey(k)
			return
		case SSHFormat1:
			err = ErrUnsuitableKeyType
			return
		default:
			err = ErrUnknownKeyFormat
			return
		}
	case *ecdsa.PrivateKey:
		switch sf {
		case SSHFormatOpenSSH:
			output, err = serializeOpenSSH(key, password, comment)
			return
		case SSHFormat2:
			output, err = Pkcs8Pem.Serialize(k, args)
			return
		case SSHFormat1:
			err = ErrUnsuitableKeyType
			return
		default:
			err = ErrUnknownKeyFormat
			return
		}
	case ed25519.PrivateKey:
		switch sf {
		case SSHFormatOpenSSH:
			output, err = serializeOpenSSH(key, password, comment)
			return
		case SSHFormat2, SSHFormat1:
			err = ErrUnsuitableKeyType
			return
		default:
			err = ErrUnknownKeyFormat
			return
		}
	case *rsa.PublicKey:
		switch sf {
		case SSHFormat1:
			output, err = ssh1SerializePublicKey(k, comment)
			return
		case SSHFormat2, SSHFormatOpenSSH:
			output, err = ssh2SerializePublicKey(k, comment)
			return
		default:
			err = ErrUnknownKeyFormat
			return
		}
	case *dsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		switch sf {
		case SSHFormat1:
			err = ErrUnsuitableKeyType
			return
		case SSHFormat2, SSHFormatOpenSSH:
			output, err = ssh2SerializePublicKey(key, comment)
			return
		default:
			err = ErrUnknownKeyFormat
			return
		}
	default:
		err = ErrUnsuitableKeyType
		return
	}
}

// Deserialize converts bytes in this format to a key.
//
// args is a collection of format-dependent parameters.
// rest is anything left over after the parse.
func (sf SSHFormat) Deserialize(input []byte, args map[string]string) (key interface{}, rest []byte, err error) {
	if ssh1IsPrivateKey(input) {
		rest, key, _, err = ssh1ParsePrivateKey(input)
		return
	}
	if rest, key, _, err = ssh1ParsePublicKey(input); err == nil {
		return
	}
	// Private keys are all some kind of PEM
	var block *pem.Block
	block, rest = pem.Decode(input)
	if block != nil {
		// ssh.ParseRawPrivateKey requires rest=""
		input = pem.EncodeToMemory(block)
		if password, ok := args["password"]; ok {
			if key, err = ssh.ParseRawPrivateKeyWithPassphrase(input, []byte(password)); err != nil {
				return
			}
		} else {
			if key, err = ssh.ParseRawPrivateKey(input); err != nil {
				switch err.(type) {
				case *ssh.PassphraseMissingError:
					err = ErrPasswordRequired
				}
				return
			}
		}
		switch k := key.(type) {
		case *ed25519.PrivateKey:
			key = *k
		}
		return
	}
	// Public keys are single-line
	var pk ssh.PublicKey
	if pk, _, _, rest, err = ssh.ParseAuthorizedKey(input); err != nil {
		return
	}
	// ssh.ParseAuthorizedKey does not consume the newline, but our
	// callers generally expect that we do.
	if len(rest) > 0 && rest[0] == '\n' {
		rest = rest[1:]
	}
	key = pk.(ssh.CryptoPublicKey).CryptoPublicKey()
	return
}

// Recognize returns an indicator of how well the input fits the format.
//
// Is is intended to do only a lightweight parse.
// For instance it need not completely deserialize binary data to see if it fits a given ASN.1 syntax.
//
// args is a collection of format-dependent parameters (possibly aimed at different formats).
// err may optionally be set (if fits==false) to document why the key was not recognized.
func (sf SSHFormat) Recognize(input []byte, args map[string]string) (fits Fit, err error) {
	// ssh1 format for private keys has a magic string at the start
	if ssh1IsPrivateKey(input) {
		if sf == SSHFormat1 {
			fits = UnambiguousFit
		} else {
			fits = AmbiguousFit
		}
		return
	}
	// ssh2/openssh private keys are PEM files
	if b, _ := pem.Decode(input); b != nil {
		switch b.Type {
		case opensshPemType:
			if sf == SSHFormatOpenSSH {
				fits = UnambiguousFit
			} else {
				fits = AmbiguousFit
			}
			return
		case "RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY":
			fits = AmbiguousFit // clash with PKCS#1, PKCS#8
			return
		default:
			fits = DoesNotFit
			return
		}
	}
	// ssh2/openssh public keys start with the key type
	bits := bytes.Split(input, []byte(" "))
	switch string(bits[0]) {
	case "ssh-dss", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-ed25519":
		if sf == SSHFormat1 {
			fits = AmbiguousFit
		} else {
			fits = UnambiguousFit
		}
		return
	}
	// ssh1 public keys are BITS N E COMMENT
	if _, _, _, err = ssh1ParsePublicKey(input); err == nil {
		if sf == SSHFormat1 {
			fits = UnambiguousFit
		} else {
			fits = AmbiguousFit
		}
		return
	}
	fits = DoesNotFit
	return
}

// Name returns the name of this format.
func (sf SSHFormat) Name() string {
	switch sf {
	case SSHFormat1:
		return "ssh1"
	case SSHFormat2:
		return "ssh2"
	case SSHFormatOpenSSH:
		return "openssh"
	default:
		log.Panicf("unrecognized SSH format %d", sf)
		return ""
	}
}

// Description returns the description of this format
func (sf SSHFormat) Description() string {
	switch sf {
	case SSHFormat1:
		return "SSH1 format"
	case SSHFormat2:
		return "OpenSSH format up to 6.4"
	case SSHFormatOpenSSH:
		return "OpenSSH format from 6.5"
	default:
		log.Panicf("unrecognized SSH format %d", sf)
		return ""
	}
}

func init() {
	registerKeyFormat(SSHFormat1)
	registerKeyFormat(SSHFormat2)
	registerKeyFormat(SSHFormatOpenSSH)
}
