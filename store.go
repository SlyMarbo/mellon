package mellon

import (
	"bytes"
	"code.google.com/p/go.crypto/scrypt"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
)

var MAGIC_BYTES = []byte("MELLON_PASSWORD_MANAGER:")
var MAGIC_BYTES_LEN = len(MAGIC_BYTES)

// SecureStore contains a set of encrypted passwords
// for a single user. Each represents the password
// for a service.
type SecureStore struct {
	Passwords []*StoredPassword
}

// NewSecureStore allocates and returns a new
// SecureStore.
func NewSecureStore() *SecureStore {
	return &SecureStore{
		Passwords: make([]*StoredPassword, 0),
	}
}

// ImportSecureStore takes a data source (such as a file) and
// reads, decrypts, and parses the data to instantiate a
// SecureStore.
func ImportSecureStore(input io.Reader, master *SecureData) (*SecureStore, error) {

	{ // Check the magic bytes.
		magic, err := read(input, MAGIC_BYTES_LEN)
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(MAGIC_BYTES, magic) {
			return nil, errors.New("Error: Input data does not contain a SecureStore.")
		}
	}

	// Read in the data.
	encryptedData, err := ioutil.ReadAll(input)
	if err != nil {
		return nil, err
	}

	// Extract the AES and scrypt parameters.
	data, salt, iv, N, r, p, err := extractCryptoDetails(encryptedData)
	if err != nil {
		return nil, err
	}
	encryptedData = nil

	// Generate the key.
	key, err := scrypt.Key(master.Bytes(), salt.Bytes(), N, r, p, 32)
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
	decrypter := cipher.NewCBCDecrypter(block, iv.Bytes())

	// Decrypt the store.
	size := len(data)
	plaintext := make([]byte, size)
	decrypter.CryptBlocks(plaintext, data)

	// Scrub the ciphertext.
	Secure(data).Delete()

	// Check and remove the padding.
	padding := int(plaintext[size-1])
	if padding < 1 || padding > aes.BlockSize {
		return nil, errors.New("Error: Password padding is invalid.")
	}
	for i := 0; i < padding; i++ {
		if plaintext[size-(i+1)] != byte(padding) {
			return nil, errors.New("Error: Password padding is invalid.")
		}
	}
	size -= padding

	// Scrub the padding, to hide
	// the length of the plaintext.
	Secure(plaintext[size:]).Delete()
	plaintext = plaintext[:size]

	// Decompress and parse the data.
	gr, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return nil, err
	}
	jd := json.NewDecoder(gr)
	ss := new(SecureStore)
	err = jd.Decode(&ss)
	if err != nil {
		return nil, err
	}
	if err = gr.Close(); err != nil {
		return nil, err
	}

	return ss, nil
}

// Delete removes the SecureStore's contents entirely from memory.
func (s *SecureStore) Delete() {
	if s == nil || s.Passwords == nil {
		return
	}
	for _, password := range s.Passwords {
		if password != nil {
			password.Delete()
		}
	}
	s.Passwords = nil
}

// Export marshals the SecureStore into JSON, compresses the data with
// GZIP, and then uses the master password to encrypt the compressed
// data. This is finally written to the given output.
func (s *SecureStore) Export(output io.Writer, master *SecureData, N, r, p int) error {
	// Make the salt.
	salt, err := read(rand.Reader, aes.BlockSize)
	if err != nil {
		return err
	}

	// Make the IV.
	iv, err := read(rand.Reader, aes.BlockSize)
	if err != nil {
		return err
	}

	// Prepare the crypto details.
	details := make([]byte, 12+(2*aes.BlockSize))
	x := aes.BlockSize
	for i := 0; i < aes.BlockSize; i++ {
		details[i] = salt[i]
		details[x+i] = iv[i]
	}
	x += aes.BlockSize
	details[x+0] = byte(uint32(N) >> 24)
	details[x+1] = byte(uint32(N) >> 16)
	details[x+2] = byte(uint32(N) >> 8)
	details[x+3] = byte(N)
	x += 4
	details[x+0] = byte(uint32(r) >> 24)
	details[x+1] = byte(uint32(r) >> 16)
	details[x+2] = byte(uint32(r) >> 8)
	details[x+3] = byte(r)
	x += 4
	details[x+0] = byte(uint32(p) >> 24)
	details[x+1] = byte(uint32(p) >> 16)
	details[x+2] = byte(uint32(p) >> 8)
	details[x+3] = byte(p)

	// Encode and compress the store.
	plaintext := new(SecureData)
	gw, err := gzip.NewWriterLevel(plaintext, gzip.BestCompression)
	if err != nil {
		return err
	}
	je := json.NewEncoder(gw)
	err = je.Encode(s)
	if err != nil {
		return err
	}
	err = gw.Close()
	if err != nil {
		return err
	}

	// Prepare and pad the plaintext.
	padding := aes.BlockSize - (plaintext.Len() % aes.BlockSize)
	plaintext.Pad(padding)
	size := plaintext.Len()
	ciphertext := make([]byte, size)

	// Ensure the plaintext isn't leaked.
	defer plaintext.Delete()

	// Generate the key.
	key, err := scrypt.Key(master.Bytes(), salt, N, r, p, 32)
	if err != nil {
		return err
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
		return err
	}
	encrypter := cipher.NewCBCEncrypter(block, iv)

	// Encrypt the data.
	encrypter.CryptBlocks(ciphertext, plaintext.Bytes())

	// Write the magic bytes.
	err = write(output, MAGIC_BYTES)
	if err != nil {
		return err
	}

	// Write the crypto details.
	err = write(output, details)
	if err != nil {
		return err
	}

	// Write the data.
	err = write(output, ciphertext)
	if err != nil {
		return err
	}

	return nil
}

// HasService returns a bool indicating whether ther is a password
// stored for the given service.
func (s *SecureStore) HasService(service []byte) bool {
	if s.Services() == 0 {
		return false
	}

	for _, password := range s.Passwords {
		if bytes.Equal(password.Service, service) {
			return true
		}
	}

	return false
}

// NewStoredPassword places the given password in the SecureStore.
func (s *SecureStore) NewStoredPassword(master, plaintext *SecureData, service []byte, N, r, p int) error {
	// Ensure the service isn't already taken.
	if s.HasService(service) {
		return errors.New("Error: Service is already registered.")
	}

	// Make the password.
	password, err := NewStoredPassword(master, plaintext.Bytes(), service, N, r, p)
	if err != nil {
		return err
	}

	// Make sure there's space for the new password in the store.
	l := len(s.Passwords)
	if l == cap(s.Passwords) {
		// Allocate double what's needed, for future growth.
		newSlice := make([]*StoredPassword, l, (l+1)*2)
		for i := range s.Passwords {
			newSlice[i] = s.Passwords[i]
			s.Passwords[i] = nil
		}

		// Update the pointers.
		s.Passwords = newSlice
		newSlice = nil
	}

	// Store the new password.
	s.Passwords = append(s.Passwords, password)

	return nil
}

// Service retrieves the data for the given service, decrypts it,
// and returns the service's password.
func (s *SecureStore) Service(service []byte, master *SecureData) (*SecureData, error) {
	// Find the StoredPassword.
	for _, password := range s.Passwords {
		if bytes.Equal(service, password.Service) {
			return password.Decrypt(master)
		}
	}

	return nil, errors.New("Error: Service not found.")
}

// Services returns the number of services for which a password is
// being stored.
func (s *SecureStore) Services() int {
	if s == nil || s.Passwords == nil {
		return 0
	}
	return len(s.Passwords)
}

// extractCryptoDetails reads the salt, IV, and scrypt configuration
// details from the beginning of a file.
func extractCryptoDetails(inputData []byte) (data []byte, salt, iv *SecureData, N, r, p int, err error) {
	if len(inputData) < 12+(2*aes.BlockSize) {
		return nil, nil, nil, 0, 0, 0, errors.New("Error: Input data is of insufficient length.")
	}
	salt = Secure(inputData[:aes.BlockSize])
	inputData = inputData[aes.BlockSize:]
	iv = Secure(inputData[:aes.BlockSize])
	inputData = inputData[aes.BlockSize:]
	config := inputData[:12]
	inputData = inputData[12:]

	N = int(bytesToUint32(config[0:4]))
	r = int(bytesToUint32(config[4:8]))
	p = int(bytesToUint32(config[8:12]))

	return inputData, salt, iv, N, r, p, nil
}
