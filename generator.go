package mellon

import (
	"errors"
	"unicode/utf8"
)

// GeneratePassword takes a length and a set of permissible
// characters and builds a highly random password accordingly.
func GeneratePassword(length int, chars []byte) ([]byte, error) {
	charsetLen := len(chars)

	// Validate the input.
	if chars == nil || charsetLen == 0 || utf8.Valid(chars) {
		return nil, errors.New("Error: Invalid or empty character set.")
	}
	if charsetLen != utf8.RuneCount(chars) {
		return nil, errors.New("Error: Character set contains UTF-8 runes outside the ASCII set.")
	}
	if length <= 0 {
		return nil, errors.New("Error: Length is not larger than zero.")
	}

	// Make sure there are no duplications in the charset.
	check := make([]bool, 255)
	charset := new(SecureData)
	charset.Make(0, charsetLen)
	for _, c := range chars {
		if !check[int(c)] {
			check[int(c)] = true
			charset.Append(c)
		}
	}
	chars = charset.Bytes()

	// Generate the password.
	out := make([]byte, charsetLen)
	for i := 0; i < length; i++ {
		index, err := randInt(charsetLen)
		if err != nil {
			return nil, err
		}
		out[i] = chars[index]
	}

	return out, nil
}
