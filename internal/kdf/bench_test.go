package kdf

import "testing"

func BenchmarkHash(b *testing.B) {
	p, _ := Hash([]byte("0123456789"), []byte("ad"), nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Verify([]byte("0123456789"), []byte("ad"))
	}
}
