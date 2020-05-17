package keyremix

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sshDeserializeCase struct {
	name    string
	input   string
	args    map[string]string
	keytype interface{}
	format  SSHFormat
	exact   bool
	fit     Fit
}

type sshSerializeCase struct {
	name        string
	input       interface{}
	format      SSHFormat
	args        map[string]string
	deserialize bool
}

func TestSSH(t *testing.T) {
	generateTestKeys()

	t.Run("Deserialize", func(t *testing.T) {
		var sshDeserializeCases = []sshDeserializeCase{
			{
				name:    "ssh1rsa",
				input:   ssh1rsa,
				args:    nil,
				keytype: &rsa.PrivateKey{},
				format:  SSHFormat1,
				exact:   false,
				fit:     UnambiguousFit,
			},
			{
				name:    "ssh1rsapub",
				input:   ssh1rsapub,
				args:    map[string]string{"comment": "richard@araminta"},
				keytype: &rsa.PublicKey{},
				format:  SSHFormat1,
				exact:   true,
				fit:     UnambiguousFit,
			},
			{
				name:    "ssh2rsa",
				input:   ssh2rsa,
				args:    map[string]string{"comment": "richard@araminta"},
				keytype: &rsa.PrivateKey{},
				format:  SSHFormat2,
				exact:   true,
				fit:     AmbiguousFit,
			},
			{
				name:    "ssh2rsapub",
				input:   ssh2rsapub,
				args:    map[string]string{"comment": "richard@araminta"},
				keytype: &rsa.PublicKey{},
				format:  SSHFormat2,
				exact:   true,
				fit:     UnambiguousFit,
			},
			{
				name:    "ssh2rsapp",
				input:   ssh2rsapp,
				args:    map[string]string{"password": "testtest"},
				keytype: &rsa.PrivateKey{},
				format:  SSHFormat2,
				exact:   false,
				fit:     AmbiguousFit,
			},
			{
				name:    "ssh2dsa",
				input:   ssh2dsa,
				args:    nil,
				keytype: &dsa.PrivateKey{},
				format:  SSHFormat2,
				exact:   false,
				fit:     AmbiguousFit,
			},
			{
				name:    "ssh2dsapub",
				input:   ssh2dsapub,
				args:    map[string]string{"comment": "richard@araminta"},
				keytype: &dsa.PublicKey{},
				format:  SSHFormat2,
				exact:   true,
				fit:     UnambiguousFit,
			},
			{
				name:    "opensshrsa",
				input:   opensshrsa,
				args:    nil,
				keytype: &rsa.PrivateKey{},
				format:  SSHFormatOpenSSH,
				exact:   false,
				fit:     UnambiguousFit,
			},
			{
				name:    "opensshrsapub",
				input:   opensshrsapub,
				args:    map[string]string{"comment": "richard@araminta"},
				keytype: &rsa.PublicKey{},
				format:  SSHFormatOpenSSH,
				exact:   true,
				fit:     UnambiguousFit,
			},
			{
				name:    "opensshrsapp",
				input:   opensshrsapp,
				args:    map[string]string{"password": "testtest"},
				keytype: &rsa.PrivateKey{},
				format:  SSHFormatOpenSSH,
				exact:   false,
				fit:     UnambiguousFit,
			},
			/* not implemented by golang.org/x/crypto/ssh
			{
				name:    "ssh2dsa",
				input:   ssh2dsa,
				args:    nil,
				keytype: &dsa.PrivateKey{},
				format:  SSHFormat2,
				exact:   false,
				fit:     AmbiguousFit,
			},
			{
				name:    "ssh2dsapub",
				input:   ssh2dsapub,
				args:    nil,
				keytype: &dsa.PublicKey{},
				format:  SSHFormat2,
				exact:   true,
				fit:     UnambiguousFit,
			},
			*/
			{
				name:    "opensshecdsa",
				input:   opensshecdsa,
				args:    nil,
				keytype: &ecdsa.PrivateKey{},
				format:  SSHFormatOpenSSH,
				exact:   false,
				fit:     UnambiguousFit,
			},
			{
				name:    "opensshecdsapub",
				input:   opensshecdsapub,
				args:    map[string]string{"comment": "richard@araminta"},
				keytype: &ecdsa.PublicKey{},
				format:  SSHFormatOpenSSH,
				exact:   true,
				fit:     UnambiguousFit,
			},
			{
				name:    "opensshed25519",
				input:   opensshed25519,
				args:    nil,
				keytype: ed25519.PrivateKey{},
				format:  SSHFormatOpenSSH,
				exact:   false,
				fit:     UnambiguousFit,
			},
			{
				name:    "opensshed25519pub",
				input:   opensshed25519pub,
				args:    map[string]string{"comment": "richard@araminta"},
				keytype: ed25519.PublicKey{},
				format:  SSHFormatOpenSSH,
				exact:   true,
				fit:     UnambiguousFit,
			},
		}
		for _, c := range sshDeserializeCases {
			t.Run(c.name, func(t *testing.T) {
				input := []byte(c.input)
				var err error
				var rest []byte
				var key interface{}
				var fit Fit
				// Check that key recognition works
				fit, err = c.format.Recognize(input, c.args)
				require.NoError(t, err)
				assert.Equal(t, c.fit, fit)
				// Check deserialization
				key, rest, err = c.format.Deserialize(input, c.args)
				require.NoError(t, err)
				assert.IsType(t, c.keytype, key)
				assert.Equal(t, 0, len(rest))
				if _, ok := c.args["password"]; !ok { // Can't re-encrypt
					var reserialized []byte
					reserialized, err = c.format.Serialize(key, c.args)
					require.NoError(t, err)
					if c.exact { // Some key types don't serialize the same way every time
						assert.Equal(t, input, reserialized)
					}
					var key2 interface{}
					key2, rest, err = c.format.Deserialize(reserialized, c.args)
					require.NoError(t, err)
					assert.Equal(t, key, key2)
				}
			})
		}
	})
	t.Run("Serialize", func(t *testing.T) {
		sshSerializeCases := []sshSerializeCase{
			{
				name:        "ssh1rsa",
				input:       rsa1024,
				format:      SSHFormat1,
				args:        nil,
				deserialize: true,
			},
			{
				name:        "ssh2rsa",
				input:       rsa1024,
				format:      SSHFormat2,
				args:        nil,
				deserialize: true,
			},
			{
				name:        "opensshrsa",
				input:       rsa1024,
				format:      SSHFormatOpenSSH,
				args:        nil,
				deserialize: true,
			},
			{
				name:        "ssh2dsa",
				input:       dsa2048,
				format:      SSHFormat2,
				args:        nil,
				deserialize: true,
			},
			{
				name:        "opensshdsa",
				input:       dsa2048,
				format:      SSHFormatOpenSSH,
				args:        nil,
				deserialize: false, // not implemented by golang.org/x/crypto/ssh
			},
			{
				name:        "ssh2ecdsa",
				input:       ecdsa384,
				format:      SSHFormat2,
				args:        nil,
				deserialize: true,
			},
			{
				name:        "opensshecdsa",
				input:       ecdsa384,
				format:      SSHFormatOpenSSH,
				args:        nil,
				deserialize: true,
			},
			{
				name:        "opensshed25519",
				input:       ed25519key,
				format:      SSHFormatOpenSSH,
				args:        nil,
				deserialize: true,
			},
		}
		for _, c := range sshSerializeCases {
			t.Run(c.name, func(t *testing.T) {
				t.Run("Private", func(t *testing.T) {
					output, err := c.format.Serialize(c.input, c.args)
					require.NoError(t, err)
					if c.deserialize {
						var key2 interface{}
						key2, _, err = c.format.Deserialize(output, c.args)
						require.NoError(t, err)
						assert.Equal(t, c.input, key2)
					}
				})
				t.Run("Public", func(t *testing.T) {
					var key interface{}
					var err error
					key, err = GetPublicKey(c.input)
					require.NoError(t, err)
					var output []byte
					output, err = c.format.Serialize(key, c.args)
					require.NoError(t, err)
					var key2 interface{}
					key2, _, err = c.format.Deserialize(output, c.args)
					require.NoError(t, err)
					assert.Equal(t, key, key2)
				})
			})
		}
	})
}
