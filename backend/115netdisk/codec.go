package netdisk115

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/pierrec/lz4/v4"
)

// ossSHA1Context encodes a block-aligned SHA1 prefix for independent OSS parts.
func ossSHA1Context(h encoding.BinaryMarshaler) (string, error) {
	state, err := h.MarshalBinary()
	if err != nil {
		return "", err
	}
	if len(state) != 96 || string(state[:4]) != "sha\x01" {
		return "", errors.New("invalid SHA1 state encoding")
	}
	length := binary.BigEndian.Uint64(state[88:])
	if length%sha1.BlockSize != 0 {
		return "", errors.New("OSS SHA1 context requires a block-aligned prefix")
	}
	bits := length * 8
	fields := map[string]string{
		"hash_type": "sha1", "Nl": strconv.FormatUint(uint64(uint32(bits)), 10),
		"Nh": strconv.FormatUint(bits>>32, 10), "data": "", "num": "0",
	}
	for i := range 5 {
		fields["h"+strconv.Itoa(i)] = strconv.FormatUint(uint64(binary.BigEndian.Uint32(state[4+i*4:])), 10)
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(body), nil
}

const (
	ecRemotePublic    = "390457a29257cd2320e5d6d143322fa4bb8a3cf9d3cc623ef5edac62b7678a89c91a83ba800d6129f522d034c895dd2465243addc250953beeba"
	ecSalt            = "^j>WD3Kr?J2gLFjD4W2y@"
	m115TableHex      = "f0e569aebfdcbf8a1a45e8be7da673b8de8fe7c445da86c49b648b146ab4f1aa3801359e26692c86006b4fa5363462a62a966818f24afdbd6b978f4d8f8913b76c8e93ed0e0d483ed72f88d8fefe7e8650954fd1eb832634db667b9c7e9d7a8132eab633de3aa95934663baaba816048b9d5819cf86c8477ff5478265fbee81e369f34805c452c9b76d51b8fccc3b8f5"
	m115ModulusHex    = "8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683"
	maxDecodedControl = 4 << 20
)

type ecContext struct {
	public [30]byte
	secret [28]byte
}

func newECContext() (*ecContext, error) {
	curve := elliptic.P224()
	private, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	remote, err := hex.DecodeString(ecRemotePublic)
	if err != nil {
		return nil, err
	}
	rx, ry := elliptic.Unmarshal(curve, remote[1:])
	if rx == nil {
		return nil, errors.New("invalid EC115 server point")
	}
	sx, _ := curve.ScalarMult(rx, ry, private)
	ctx := &ecContext{}
	ctx.public[0], ctx.public[1] = 0x1d, 2+byte(y.Bit(0))
	x.FillBytes(ctx.public[2:])
	sx.FillBytes(ctx.secret[:])
	return ctx, nil
}

func (c *ecContext) queryToken(userID uint32, now time.Time) string {
	var token [48]byte
	micros := now.UnixMicro() % 1_000_000
	r1, r2 := byte(micros), byte(micros/1000)
	copy(token[:15], c.public[:15])
	binary.LittleEndian.PutUint32(token[16:20], userID)
	binary.LittleEndian.PutUint32(token[20:24], uint32(now.Unix()))
	for i := 0; i < 24; i++ {
		token[i] ^= r1
	}
	token[15] = r1
	copy(token[24:39], c.public[15:])
	binary.LittleEndian.PutUint32(token[40:44], 0)
	for i := 24; i < 44; i++ {
		token[i] ^= r2
	}
	token[39] = r2
	binary.LittleEndian.PutUint32(token[44:], crc32.ChecksumIEEE(append([]byte(ecSalt), token[:44]...)))
	return base64.StdEncoding.EncodeToString(token[:])
}

func (c *ecContext) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.secret[:16])
	if err != nil {
		return nil, err
	}
	result := make([]byte, (len(plaintext)+15)/16*16)
	copy(result, plaintext)
	cipher.NewCBCEncrypter(block, c.secret[12:]).CryptBlocks(result, result)
	return result, nil
}

func (c *ecContext) decode(packet []byte) ([]byte, error) {
	if len(packet) > maxDecodedControl {
		return nil, errors.New("EC115 response exceeds size limit")
	}
	trimmed := bytes.TrimSpace(packet)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return trimmed, nil
	}
	if len(packet) < 12 {
		return nil, errors.New("short EC115 response")
	}
	tail := packet[len(packet)-12:]
	if crc32.ChecksumIEEE(append([]byte(ecSalt), tail[:8]...)) != binary.LittleEndian.Uint32(tail[8:]) {
		return nil, errors.New("invalid EC115 trailer CRC")
	}
	if tail[4] > 1 || tail[5] > 1 {
		return nil, errors.New("invalid EC115 response flags")
	}
	data := append([]byte(nil), packet[:len(packet)-12]...)
	if tail[5] == 1 {
		if len(data)%16 != 0 || len(data) == 0 {
			return nil, errors.New("invalid EC115 ciphertext length")
		}
		block, err := aes.NewCipher(c.secret[:16])
		if err != nil {
			return nil, err
		}
		cipher.NewCBCDecrypter(block, c.secret[12:]).CryptBlocks(data, data)
		for removed := 0; removed < 16 && len(data) > 0 && data[len(data)-1] == 0; removed++ {
			data = data[:len(data)-1]
		}
	}
	if tail[4] == 0 {
		return data, nil
	}
	var decoded []byte
	for len(data) > 0 {
		if len(data) < 2 {
			return nil, errors.New("truncated EC115 LZ4 length")
		}
		length := int(binary.LittleEndian.Uint16(data))
		data = data[2:]
		if length == 0 || length > len(data) {
			return nil, errors.New("invalid EC115 LZ4 block length")
		}
		var buffer [8192]byte
		n, err := lz4.UncompressBlock(data[:length], buffer[:])
		if err != nil {
			return nil, err
		}
		if n <= 0 || len(decoded) > maxDecodedControl-n {
			return nil, errors.New("invalid EC115 decompressed size")
		}
		decoded = append(decoded, buffer[:n]...)
		data = data[length:]
	}
	return decoded, nil
}

func uploadToken(userID int64, timestamp, size int64, fileID, check, version string) string {
	uid := strconv.FormatInt(userID, 10)
	uidHash := md5.Sum([]byte(uid))
	prefix := "Qclm8MGWUv59TnrR0XPg"
	if version == "" {
		prefix = ""
	}
	value := prefix + fileID + strconv.FormatInt(size, 10) + check + uid + strconv.FormatInt(timestamp, 10) + hex.EncodeToString(uidHash[:]) + version
	token := md5.Sum([]byte(value))
	return hex.EncodeToString(token[:])
}

func uploadSignature(userID int64, fileID, target, userkey string) string {
	inner := sha1.Sum([]byte(strconv.FormatInt(userID, 10) + fileID + target + "100"))
	outer := sha1.Sum([]byte(userkey + hex.EncodeToString(inner[:])))
	return strings.ToUpper(hex.EncodeToString(outer[:]))
}

func m115Derive(seed []byte, length int) ([]byte, error) {
	if len(seed) != 16 || (length != 4 && length != 12) {
		return nil, errors.New("invalid M115 key input")
	}
	table, err := hex.DecodeString(m115TableHex)
	if err != nil {
		return nil, err
	}
	key := make([]byte, length)
	for i := range key {
		key[i] = (seed[i] + table[i*length]) ^ table[(length-1-i)*length]
	}
	return key, nil
}

func m115XOR(data, key []byte) []byte {
	result := make([]byte, len(data))
	prefix := len(data) % 4
	for i, value := range data {
		index := i
		if i >= prefix {
			index -= prefix
		}
		result[i] = value ^ key[index%len(key)]
	}
	return result
}

func reversed(data []byte) []byte {
	result := append([]byte(nil), data...)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

func m115PublicKey() (*rsa.PublicKey, error) {
	n, ok := new(big.Int).SetString(m115ModulusHex, 16)
	if !ok {
		return nil, errors.New("invalid M115 modulus")
	}
	return &rsa.PublicKey{N: n, E: 65537}, nil
}

func m115Encode(plaintext []byte, seed []byte) (string, error) {
	key, err := m115Derive(seed, 4)
	if err != nil {
		return "", err
	}
	public, err := m115PublicKey()
	if err != nil {
		return "", err
	}
	long := []byte{0x78, 0x06, 0xad, 0x4c, 0x33, 0x86, 0x5d, 0x18, 0x4c, 0x01, 0x3f, 0x46}
	data := append(append([]byte(nil), seed...), m115XOR(reversed(m115XOR(plaintext, key)), long)...)
	var encrypted []byte
	for len(data) > 0 {
		length := min(len(data), 117)
		block, err := rsa.EncryptPKCS1v15(rand.Reader, public, data[:length])
		if err != nil {
			return "", err
		}
		encrypted = append(encrypted, block...)
		data = data[length:]
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func m115Decode(encoded string, seed []byte) ([]byte, error) {
	if len(encoded) > maxDecodedControl {
		return nil, errors.New("M115 response exceeds size limit")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%128 != 0 {
		return nil, errors.New("invalid M115 RSA block length")
	}
	public, err := m115PublicKey()
	if err != nil {
		return nil, err
	}
	var data []byte
	for offset := 0; offset < len(ciphertext); offset += 128 {
		value := new(big.Int).SetBytes(ciphertext[offset : offset+128])
		if value.Cmp(public.N) >= 0 {
			return nil, errors.New("M115 RSA value exceeds modulus")
		}
		var block [128]byte
		new(big.Int).Exp(value, big.NewInt(int64(public.E)), public.N).FillBytes(block[:])
		if block[0] != 0 || block[1] != 1 {
			return nil, errors.New("invalid M115 response padding")
		}
		end := 2
		for end < len(block) && block[end] == 0xff {
			end++
		}
		if end < 10 || end >= len(block) || block[end] != 0 {
			return nil, errors.New("invalid M115 response padding length")
		}
		data = append(data, block[end+1:]...)
	}
	if len(data) < 16 {
		return nil, errors.New("short M115 response seed")
	}
	long, err := m115Derive(data[:16], 12)
	if err != nil {
		return nil, err
	}
	short, err := m115Derive(seed, 4)
	if err != nil {
		return nil, err
	}
	decoded := m115XOR(reversed(m115XOR(data[16:], long)), short)
	if len(decoded) > maxDecodedControl {
		return nil, fmt.Errorf("M115 decoded response exceeds %d bytes", maxDecodedControl)
	}
	return decoded, nil
}
