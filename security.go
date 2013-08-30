package mellon

// SecureData can be used similarly to
// a slice of bytes, but it provides
// various security methods to ensure
// secure data is not leaked.
type SecureData struct {
	data []byte
}

// Wrap a byte slice in SecureData.
func Secure(data []byte) *SecureData {
	return &SecureData{data: data}
}

// Append functions identically to append, but ensures
// the data is not leaked into other areas of memory.
func (s *SecureData) Append(data ...byte) {
	if s.data == nil || len(s.data) == 0 {
		s.data = make([]byte, len(data))
	}

	l := len(s.data)
	if l+len(data) > cap(s.data) { // Reallocate.

		// Allocate double what's needed, for future growth.
		newSlice := make([]byte, l, (l+len(data))*2)
		copy(newSlice, s.data)

		// Overwrite the old slice so secure data isn't leaked.
		s.Delete()

		// Update the pointers.
		s.data = newSlice
		newSlice = nil
	}

	// Grow slice and copy data.
	s.data = s.data[:l+len(data)]
	for i, c := range data {
		s.data[l+i] = c
	}
}

// Bytes returns the data being secured.
func (s *SecureData) Bytes() []byte {
	return s.data
}

// Delete ensures the data is overwritten
// before being discarded so that it
// should
func (s *SecureData) Delete() {
	if s.data == nil {
		return
	}
	zero(s.data)
	one(s.data)
	s.data = nil
}

// Len returns the length of the secured
// data in bytes.
func (s *SecureData) Len() int {
	if s.data == nil {
		return 0
	}
	return len(s.data)
}

// Make allocates the secured data with the
// given length and capacity.
func (s *SecureData) Make(length, capacity int) {
	if s.data != nil {
		s.Delete()
	}
	s.data = make([]byte, length, capacity)
}

// Pad appends the data with the padding
// value a number of times equal to the
// padding value.
func (s *SecureData) Pad(value int) {
	padding := make([]byte, value)
	for i := range padding {
		padding[i] = byte(value)
	}
	s.Append(padding...)
}

// String returns the secured data in
// string form.
func (s *SecureData) String() string {
	return string(s.data)
}

// Write fulfils the io.Writer interface
// and ensures no data is leaked.
func (s *SecureData) Write(data []byte) (int, error) {
	l := len(data)
	s.Append(data...)
	return l, nil
}

// zero ensures all bits in
// the given slice are set
// to zero.
func zero(slice []byte) {
	for i := range slice {
		slice[i] = 0x00
	}
}

// one ensures all bits in
// the given slice are set
// to one.
func one(slice []byte) {
	for i := range slice {
		slice[i] = 0xff
	}
}
