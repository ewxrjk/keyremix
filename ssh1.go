package keyremix

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"fmt"

	"math/big"

	"github.com/golang/go/src/math/rand"
)

// ssh1 key formats:
//
//    Public keys are: BITS E N COMMENT
//      where BITS, E and N are in decimal.
//
//    Private keys have the following format:
//      byte[]  "SSH PRIVATE KEY FILE FORMAT 1.1\n\0"
//      uint8   cipher    # 0 for none, 3 for 3DES CBC
//      uint32  reserved  # set to 0
//      uint32  nbits
//      bignum1 n
//      bignum1 e
//      string  comment
//      byte[]  ciphertext
//
//    The plaintext containing the private key is:
//      uint16  check1   # random
//      uint16  check2   # need check1=check2
//      bignum1 d
//      bignum1 iqmp
//      bignum1 q
//      bignum1 p
//      byte[]  padding  # 0 bytes to make up to a multiple of 8
//
//    bignum1 is slightly different from the other formats:
//      uint16  nbits
//      byte[]  I2OSP(n, (nbits+7)/8
//

const ssh1Indicator = "SSH PRIVATE KEY FILE FORMAT 1.1\n\x00"

// ssh1ParsePublicKey parses an SSH1 public key.
func ssh1ParsePublicKey(input []byte) (rest []byte, key *rsa.PublicKey, comment string, err error) {
	// One key per line
	newline := bytes.Index(input, []byte{'\n'})
	if newline >= 0 {
		rest = input[newline+1:]
		input = input[:newline]
	}
	bits := bytes.Split(input, []byte{' '})
	if len(bits) < 3 || len(bits) > 4 {
		err = ErrCannotParseKey
		return
	}
	values := []*big.Int{}
	for _, bit := range bits {
		v := big.NewInt(0)
		if _, ok := v.SetString(string(bit), 10); !ok {
			break
		}
		values = append(values, v)
	}
	if len(values) != 3 || !values[0].IsUint64() || values[0].Uint64() != uint64(values[2].BitLen()) ||
		!values[1].IsUint64() || values[1].Uint64() < 3 || values[1].Uint64() > 0xFFFFFFFF {
		err = ErrCannotParseKey
		return
	}
	key = &rsa.PublicKey{
		N: values[2],
		E: int(values[1].Uint64()),
	}
	if len(bits) >= 4 {
		comment = string(bits[3])
	}
	return
}

func ssh1SerializePublicKey(key *rsa.PublicKey, comment string) (output []byte, err error) {
	s := fmt.Sprintf("%v %v %v %s\n", key.N.BitLen(), key.E, key.N, comment)
	output = []byte(s)
	return
}

func ssh1IsPrivateKey(input []byte) bool {
	ilen := len(ssh1Indicator)
	return len(input) > ilen && bytes.Compare(input[:ilen], []byte(ssh1Indicator)) == 0
}

func ssh1ParsePrivateKey(input []byte) (rest []byte, key *rsa.PrivateKey, comment string, err error) {
	ilen := len(ssh1Indicator)
	if !ssh1IsPrivateKey(input) {
		err = ErrCannotParseKey
		return
	}
	input = input[ilen:]
	var cipher uint8
	var check1, check2 uint16
	var e *big.Int
	k := &rsa.PrivateKey{
		Primes: make([]*big.Int, 2),
	}
	if input, cipher, err = ssh1ParseUint8(input); err != nil {
		return
	}
	if cipher != 0 {
		err = ErrPasswordRequired
		return
	}
	if input, _, err = ssh1ParseUint32(input); err != nil {
		return
	}
	if input, _, err = ssh1ParseUint32(input); err != nil {
		return
	}
	if input, k.N, err = ssh1ParseBignum(input); err != nil {
		return
	}
	if input, e, err = ssh1ParseBignum(input); err != nil {
		return
	}
	if !e.IsUint64() || e.Uint64() > 0xFFFFFFFF {
		err = ErrCannotParseKey
		return
	}
	k.E = int(e.Uint64())
	if input, comment, err = ssh1ParseString(input); err != nil {
		return
	}
	if input, check1, err = ssh1ParseUint16(input); err != nil {
		return
	}
	if input, check2, err = ssh1ParseUint16(input); err != nil {
		return
	}
	if check1 != check2 {
		err = ErrCannotParseKey
		return
	}
	if input, k.D, err = ssh1ParseBignum(input); err != nil {
		return
	}
	if input, k.Precomputed.Qinv, err = ssh1ParseBignum(input); err != nil {
		return
	}
	if input, k.Primes[1], err = ssh1ParseBignum(input); err != nil {
		return
	}
	if input, k.Primes[0], err = ssh1ParseBignum(input); err != nil {
		return
	}
	// Fill in the missing bits
	k.Precompute()
	key = k
	return
}

func ssh1ParseUint8(input []byte) (rest []byte, b uint8, err error) {
	if len(input) < 1 {
		err = ErrCannotParseKey
		return
	}
	b = input[0]
	rest = input[1:]
	return
}

func ssh1ParseUint16(input []byte) (rest []byte, b uint16, err error) {
	if len(input) < 2 {
		err = ErrCannotParseKey
		return
	}
	b = binary.BigEndian.Uint16(input)
	rest = input[2:]
	return
}

func ssh1ParseUint32(input []byte) (rest []byte, b uint32, err error) {
	if len(input) < 4 {
		err = ErrCannotParseKey
		return
	}
	b = binary.BigEndian.Uint32(input)
	rest = input[4:]
	return
}

func ssh1ParseString(input []byte) (rest []byte, s string, err error) {
	var slen uint32
	if input, slen, err = ssh1ParseUint32(input); err != nil {
		return
	}
	if uint32(len(input)) < slen {
		err = ErrCannotParseKey
		return
	}
	s = string(input[:slen])
	rest = input[slen:]
	return
}

func ssh1ParseBignum(input []byte) (rest []byte, n *big.Int, err error) {
	var nbits uint16
	if input, nbits, err = ssh1ParseUint16(input); err != nil {
		return
	}
	nlen := (nbits + 7) / 8
	if len(input) < int(nlen) {
		err = ErrCannotParseKey
		return
	}
	n = big.NewInt(0)
	n.SetBytes(input[:nlen])
	rest = input[nlen:]
	return
}

func ssh1SerializePrivateKey(key *rsa.PrivateKey, password string, comment string) (output []byte, err error) {
	if password != "" {
		err = ErrNotImplemented
		return
	}
	output = append(output, []byte(ssh1Indicator)...)
	output = ssh1SerializeUint8(output, 0)
	output = ssh1SerializeUint32(output, 0)
	output = ssh1SerializeUint32(output, uint32(key.PublicKey.N.BitLen()))
	output = ssh1SerializeBignum(output, key.PublicKey.N)
	output = ssh1SerializeBignum(output, big.NewInt(int64(key.PublicKey.E)))
	output = ssh1SerializeString(output, comment)

	check := uint16(rand.Uint32())
	plaintext := ssh1SerializeUint16(nil, check)
	plaintext = ssh1SerializeUint16(plaintext, check)
	plaintext = ssh1SerializeBignum(plaintext, key.D)
	plaintext = ssh1SerializeBignum(plaintext, key.Precomputed.Qinv)
	plaintext = ssh1SerializeBignum(plaintext, key.Primes[1])
	plaintext = ssh1SerializeBignum(plaintext, key.Primes[0])
	for len(plaintext)%8 != 0 {
		plaintext = append(plaintext, 0)
	}

	// TODO encrypt
	output = append(output, plaintext...)
	return
}

func ssh1SerializeUint8(output []byte, b uint8) (updated []byte) {
	updated = append(output, b)
	return
}

func ssh1SerializeUint16(output []byte, b uint16) (updated []byte) {
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, b)
	updated = append(output, bs...)
	return
}

func ssh1SerializeUint32(output []byte, b uint32) (updated []byte) {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, b)
	updated = append(output, bs...)
	return
}

func ssh1SerializeString(output []byte, s string) (updated []byte) {
	output = ssh1SerializeUint32(output, uint32(len(s)))
	updated = append(output, []byte(s)...)
	return
}

func ssh1SerializeBignum(output []byte, n *big.Int) (updated []byte) {
	output = ssh1SerializeUint16(output, uint16(n.BitLen()))
	updated = append(output, n.Bytes()...)
	return
}
