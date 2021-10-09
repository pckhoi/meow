package meow

import (
	"crypto/aes"
	"encoding/binary"
)

//go:generate go run make_block.go

// Meow hash version implemented by this package.
const (
	Version     = 2
	VersionName = "0.2/Ragdoll"
)

// BlockSize is the underlying block size of Meow hash in bytes.
const BlockSize = 256

// Size of a Meow checksum in bytes.
const Size = 16

// Variables capturing the implementation. Default to the pure go fallback.
var (
	implementation = "go"
	checksum       = checksumgo
	blocks         = blocksgo
	finish         = finishgo
)

// Checksum returns the Meow checksum of data.
func Checksum(seed uint64, data []byte) [Size]byte {
	var dst [Size]byte
	checksum(seed, dst[:], data)
	return dst
}

// Checksum64 returns the 64-bit checksum of data.
func Checksum64(seed uint64, data []byte) uint64 {
	c := Checksum(seed, data)
	return binary.LittleEndian.Uint64(c[:8])
}

// Checksum32 returns the 32-bit checksum of data.
func Checksum32(seed uint64, data []byte) uint32 {
	c := Checksum(seed, data)
	return binary.LittleEndian.Uint32(c[:4])
}

// New returns a 128-bit Meow hash.
func New(seed uint64) *Digest {
	return new(seed, Size)
}

// New64 returns the 64-bit version of Meow hash.
func New64(seed uint64) *Digest {
	return new(seed, 8)
}

// New32 returns the 32-bit version of Meow hash.
func New32(seed uint64) *Digest {
	return new(seed, 4)
}

func new(seed uint64, size int) *Digest {
	return &Digest{seed: seed, size: size}
}

// Digest computes Meow hash in a streaming fashion.
type Digest struct {
	seed   uint64          // hash seed
	s      [BlockSize]byte // streams
	b      [BlockSize]byte // pending block
	n      int             // number of (initial) bytes populated in b
	t      []byte          // the trailing block of data written to the hash
	length uint64          // total length written
	size   int             // hash size in bytes
}

// Size returns the number of bytes Sum will return.
func (d *Digest) Size() int { return d.size }

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (d *Digest) BlockSize() int { return BlockSize }

// Reset resets the Hash to its initial state.
func (d *Digest) Reset() {
	for i := 0; i < BlockSize; i++ {
		d.s[i] = 0
	}
	d.n = 0
	d.length = 0
	d.t = nil
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (d *Digest) Write(p []byte) (int, error) {
	N := len(p)
	d.length += uint64(N)

	// Update trailing block.
	if len(p) >= aes.BlockSize {
		d.t = p[N-aes.BlockSize:]
	} else {
		d.t = append(d.t, p...)
	}
	if len(d.t) > aes.BlockSize {
		d.t = d.t[len(d.t)-aes.BlockSize:]
	}

	// Combine with any pending data.
	if d.n > 0 {
		n := copy(d.b[d.n:], p)
		d.n += n
		if d.n == BlockSize {
			blocks(d.s[:], d.b[:])
			d.n = 0
		}
		p = p[n:]
	}

	// Hash any entire blocks.
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		blocks(d.s[:], p[:n])
		p = p[n:]
	}

	// Keep any remaining data.
	if len(p) > 0 {
		d.n = copy(d.b[:], p)
	}

	return N, nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *Digest) Sum(b []byte) []byte {
	var dst [Size]byte
	dt := *d
	finish(dt.seed, dt.s[:], dst[:], dt.b[:d.n], dt.t, dt.length)
	return append(b, dst[:dt.size]...)
}

// SumTo copies the current hash to dst. It is essentially the zero
// allocation version of Sum. dst must be a slice of length 16.
func (d *Digest) SumTo(dst []byte) {
	finish(d.seed, d.s[:], dst, d.b[:d.n], d.t, d.length)
}

// Sum32 implements hash.Hash32 interface
func (d *Digest) Sum32() uint32 {
	return binary.LittleEndian.Uint32(d.Sum(nil))
}

// Sum64 implements hash.Hash64 interface
func (d *Digest) Sum64() uint64 {
	return binary.LittleEndian.Uint64(d.Sum(nil))
}
