// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Electronic Code Book (ECB) mode.

// ECB provides confidentiality by assigning a fixed ciphertext block to each
// plaintext block.

// rsc@golang.org: We left ECB out intentionally: it's insecure, and if needed it's
// trivial to implement.
// https://code.google.com/p/go/issues/detail?id=5597

// See NIST SP 800-38A, pp 08-09
package dot1x

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func newECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func newECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

// Convert pass to UCS-2 (UTF-16)
func ntPassword(pass string) []byte {
	buf := utf16.Encode([]rune(pass))
	enc := make([]byte, len(pass)*2)
	for i := 0; i < len(pass); i++ {
		pos := 2 * i
		binary.LittleEndian.PutUint16(enc[pos:pos+2], buf[i])
	}
	return enc
}

// MD4 hash the UCS-2 value
func ntPasswordHash(r []byte) []byte {
	d := md4.New()
	d.Write(r)
	return d.Sum(nil)
}

// Convert 7byte string into 8bit key
// https://github.com/FreeRADIUS/freeradius-server/blob/5ea87f156381174ea24340db9b450d4eca8189c9/src/modules/rlm_mschap/smbdes.c#L268
func strToKey(str []byte) []byte {
	key := make([]byte, 8)
	key[0] = str[0] >> 1
	key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2)
	key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3)
	key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4)
	key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5)
	key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6)
	key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7)
	key[7] = str[6] & 0x7F

	for i := 0; i < 8; i++ {
		key[i] = (key[i] << 1)
	}
	return key
}

// Create Response for comparison
func ntChallengeResponse(challenge []byte, passHash []byte) ([]byte, error) {
	// Pass is already encoded (NTPasswordHash)
	// ChallengeResponse
	res := make([]byte, 24)
	zPasswordHash := make([]byte, 21)

	// Set ZPasswordHash to PasswordHash zero-padded to 21 octets
	for i := 0; i < len(passHash); i++ {
		zPasswordHash[i] = passHash[i]
	}

	// DesEncrypt first 7 bytes
	{
		block, e := des.NewCipher(strToKey(zPasswordHash[:7]))
		if e != nil {
			return nil, e
		}
		mode := newECBEncrypter(block)
		mode.CryptBlocks(res, challenge)
	}

	// DesEncrypt second 7 bytes
	{
		block, e := des.NewCipher(strToKey(zPasswordHash[7:14]))
		if e != nil {
			return nil, e
		}
		mode := newECBEncrypter(block)
		mode.CryptBlocks(res[8:], challenge)
	}

	// DesEncrypt last 7 bytes
	{
		block, e := des.NewCipher(strToKey(zPasswordHash[14:]))
		if e != nil {
			return nil, e
		}
		mode := newECBEncrypter(block)
		mode.CryptBlocks(res[16:], challenge)
	}
	return res, nil
}

type Res struct {
	ChallengeResponse     []byte
	AuthenticatorResponse string
}

// SHA1 of all challenges + username
func challengeHash(peerChallenge []byte, authChallenge []byte, userName []byte) []byte {
	enc := sha1.New()
	enc.Write(peerChallenge)
	enc.Write(authChallenge)
	enc.Write(userName)
	return enc.Sum(nil)[:8]
}

// GenerateNTResponse, GenerateAuthenticatorResponse
func Encryptv2(authenticatorChallenge []byte, peerChallenge []byte, username string, pass string) (*Res, error) {
	var (
		out Res
		e   error
	)

	challenge := challengeHash(peerChallenge, authenticatorChallenge, []byte(username))
	passHash := ntPasswordHash(ntPassword(pass))

	out.ChallengeResponse, e = ntChallengeResponse(challenge, passHash)
	if e != nil {
		return nil, e
	}
	out.AuthenticatorResponse = authResponse(pass, out.ChallengeResponse, peerChallenge, authenticatorChallenge, username)

	return &out, nil
}

// HashNtPasswordHash
// Hash the MD4 to a hashhash MD4
func hashNtPasswordHash(hash []byte) []byte {
	d := md4.New()
	d.Write(hash)
	return d.Sum(nil)
}

// GenerateAuthenticatorResponse
func authResponse(pass string, ntResponse []byte, peerChallenge []byte, authChallenge []byte, userName string) string {
	var x []byte
	{
		magic := []byte{
			0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
			0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
			0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
			0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74,
		}
		hashHash := hashNtPasswordHash(ntPasswordHash(ntPassword(pass)))

		enc := sha1.New()
		enc.Write(hashHash)
		enc.Write(ntResponse)
		enc.Write(magic)
		x = enc.Sum(nil)
	}

	var y []byte
	{
		magic := []byte{
			0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
			0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
			0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
			0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
			0x6E,
		}
		challenge := challengeHash(peerChallenge, authChallenge, []byte(userName))

		enc := sha1.New()
		enc.Write(x)
		enc.Write(challenge)
		enc.Write(magic)
		y = enc.Sum(nil)
	}

	return "S=" + strings.ToUpper(fmt.Sprintf("%x", y))
}

func genChalange16B(a *[]byte) {
	var r [16]byte
	u0 := rand.Uint64()
	u1 := rand.Uint64()
	binary.LittleEndian.PutUint64(r[0:8], u0)
	binary.LittleEndian.PutUint64(r[8:16], u1)
	*a = (*a)[:0]
	*a = append(*a, r[:]...)
}
