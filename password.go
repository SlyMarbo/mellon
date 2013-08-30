package mellon

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// StoredPassword contains the data
// for an encrypted password, the
// service for which the password is
// used, and the cryptographic data
// for decryption.
type StoredPassword struct {
	EncryptedPassword []byte
	Service           []byte
	Salt              []byte
	IV                []byte
	N                 int
	R                 int
	P                 int
}

// NewStoredPassword takes a new password, the service for which
// it's used, and the master password. The new password is first
// encrypted, and then stored in a new StoredPassword. Note that
// the master and plaintext password are only deleted on success.
func NewStoredPassword(master *SecureData, plaintext, service []byte, N, r, p int) (*StoredPassword, error) {
	s := &StoredPassword{}

	// Copy the plaintext to allow padding
	// without modifying the original data.
	password := new(SecureData)
	password.Append(plaintext...)
	defer password.Delete()

	// Make the salt.
	salt, err := read(rand.Reader, aes.BlockSize)
	if err != nil {
		s.Delete()
		return nil, err
	}
	s.Salt = salt
	salt = nil

	// Make the IV.
	iv, err := read(rand.Reader, aes.BlockSize)
	if err != nil {
		s.Delete()
		return nil, err
	}
	s.IV = iv
	iv = nil

	// Store the scrypt configuration details.
	s.N = N
	s.R = r
	s.P = p
	N = 0
	r = 0
	p = 0

	// Pad the new password.
	size := password.Len()
	padding := aes.BlockSize - (size % aes.BlockSize)
	size += padding
	password.Pad(padding)

	// Generate the key.
	key, err := scrypt.Key(master.Bytes(), s.Salt, s.N, s.R, s.P, 32)
	if err != nil {
		return nil, err
	}

	// Ensure the key isn't leaked.
	securedKey := Secure(key)
	defer securedKey.Delete()

	// SECURITY_NOTE //
	// Although we can scrub the key, the
	// AES package stores two processed
	// versions in unexported variables.
	// We can't guarantee that these will
	// be removed from memory.

	// Build the encrypter.
	block, err := aes.NewCipher(key)
	if err != nil {
		s.Delete()
		return nil, err
	}
	encrypter := cipher.NewCBCEncrypter(block, s.IV)

	// Encrypt the password.
	ciphertextBytes := make([]byte, size)
	encrypter.CryptBlocks(ciphertextBytes, password.Bytes())

	// Secure the ciphertext.
	s.EncryptedPassword = ciphertextBytes
	ciphertextBytes = nil
	s.Service = service

	return s, nil
}

// Decrypt takes the master password and returns the decrypted
// password and any error.
func (s *StoredPassword) Decrypt(master *SecureData) (*SecureData, error) {

	// Make sure the stored password is correctly initialised.
	if s.Salt == nil || len(s.Salt) < aes.BlockSize {
		return nil, errors.New("Error: Salt is too short or uninitialised.")
	}
	if s.IV == nil || len(s.IV) != aes.BlockSize {
		return nil, errors.New("Error: IV is the wrong size or uninitialised.")
	}
	if len(s.EncryptedPassword)%aes.BlockSize != 0 {
		return nil, errors.New("Error: Ciphertext is not a multiple of the block size.")
	}

	// Generate the key.
	key, err := scrypt.Key(master.Bytes(), s.Salt, s.N, s.R, s.P, 32)
	if err != nil {
		return nil, err
	}

	// Ensure the key isn't leaked.
	securedKey := Secure(key)
	defer securedKey.Delete()

	// SECURITY_NOTE //
	// Although we can scrub the key, the
	// AES package stores two processed
	// versions in unexported variables.
	// We can't guarantee that these will
	// be removed from memory.

	// Build the decrypter.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCBCDecrypter(block, s.IV)

	// Decrypt the password.
	size := len(s.EncryptedPassword)
	plaintextBytes := make([]byte, size)
	decrypter.CryptBlocks(plaintextBytes, s.EncryptedPassword)

	// Check and remove the padding.
	padding := int(plaintextBytes[size-1])
	if padding < 1 || padding > aes.BlockSize {
		return nil, errors.New("Error: Password padding is invalid.")
	}
	for i := 0; i < padding; i++ {
		if plaintextBytes[size-(i+1)] != byte(padding) {
			return nil, errors.New("Error: Password padding is invalid.")
		}
	}
	size -= padding

	// Scrub the padding, to hide
	// the length of the plaintext.
	Secure(plaintextBytes[size:]).Delete()
	plaintextBytes = plaintextBytes[:size]

	// Secure the plaintext.
	plaintext := Secure(plaintextBytes)

	return plaintext, nil
}

// Delete purges the data contained in
// the StoredPassword.
func (s *StoredPassword) Delete() {
	Secure(s.EncryptedPassword).Delete()
	Secure(s.Service).Delete()
	Secure(s.Salt).Delete()
	Secure(s.IV).Delete()
	s.EncryptedPassword = nil
	s.Service = nil
	s.Salt = nil
	s.IV = nil
	s.N = 0
	s.R = 0
	s.P = 0
}
