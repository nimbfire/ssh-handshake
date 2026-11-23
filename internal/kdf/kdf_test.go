package kdf

import "testing"

func TestHashVerify(t *testing.T) {
	p, err := Hash([]byte{1, 2, 3}, []byte("ad"), nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		secret, ad string
		want       bool
	}{
		{"\x01\x02\x03", "ad", true},
		{"\x01\x02\x04", "ad", false},
		{"\x01\x02\x03", "other", false},
		{"", "ad", false},
	}
	for _, c := range cases {
		ok, err := p.Verify([]byte(c.secret), []byte(c.ad))
		if err != nil || ok != c.want {
			t.Errorf("Verify(%q,%q) = %v,%v want %v", c.secret, c.ad, ok, err, c.want)
		}
	}
}

func TestBoundaryAmbiguity(t *testing.T) {
	// (ad="a", secret="bc") must differ from (ad="ab", secret="c").
	p, _ := Hash([]byte("bc"), []byte("a"), nil)
	if ok, _ := p.Verify([]byte("c"), []byte("ab")); ok {
		t.Fatal("length prefixing is broken")
	}
}

func TestRejectsWeakOrHugeParams(t *testing.T) {
	p, _ := Hash([]byte("x"), nil, nil)
	weak := p
	weak.MemoryKiB = 8
	if _, err := weak.Verify([]byte("x"), nil); err == nil {
		t.Error("accepted downgraded memory cost")
	}
	huge := p
	huge.MemoryKiB = 1 << 30
	if _, err := huge.Verify([]byte("x"), nil); err == nil {
		t.Error("accepted huge memory cost")
	}
	alg := p
	alg.Alg = "sha256"
	if _, err := alg.Verify([]byte("x"), nil); err == nil {
		t.Error("accepted unknown algorithm")
	}
}
