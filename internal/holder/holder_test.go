// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package holder

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

// The wallet derives the holder key from its seed; these vectors are the
// wallet's own (holder-keys.ts), recomputed here so both sides are pinned
// to the same bytes.
func TestHolderKeyVectors(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	salt, _ := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	n, _ := new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
	nm1 := new(big.Int).Sub(n, big.NewInt(1))
	cases := []struct{ info, scalar, pub, commitment string }{
		{"privasys-attribute-verifier/v1",
			"21467fe9179b82d245e228cbf51f218b6c63e9723f66d49f0ebc9fb45de20a25",
			"04ee4284b840373e9615410eef21189d6fb076eb3e010cbcf1dcbfc53ebb992634d69812914d2ca2317d194d4c981c18163204ccc71996733a111f5bdb5af31e9b",
			"KEy5C9YSQSuJ1abFbMRpCGfVBud2RoTA8VrqtLJnad4"},
		{"privasys-identity-verifier/v1",
			"a8159621747befbe378ec9162bbbde947af05d99dc2baf617d0c17c235664191",
			"04ecc1745af4530da0b4ecc7eac030803b77cacfd117e60b30b6f663940ba6fc86a4a448b712878d98965de765f5765fe6c6ccaec1299756110f53fc95fef3b703",
			"g607rOJG9LvYq7X_ZSPh4MKGazeMIAvXvWW09Bm36hg"},
	}
	for _, c := range cases {
		okm, err := hkdf.Key(sha256.New, seed, nil, c.info, 48)
		if err != nil {
			t.Fatal(err)
		}
		d := new(big.Int).Mod(new(big.Int).SetBytes(okm), nm1)
		d.Add(d, big.NewInt(1))
		db := d.FillBytes(make([]byte, 32))
		if hex.EncodeToString(db) != c.scalar {
			t.Fatalf("%s: scalar %x", c.info, db)
		}
		k, err := ecdh.P256().NewPrivateKey(db)
		if err != nil {
			t.Fatal(err)
		}
		pub := k.PublicKey().Bytes()
		if hex.EncodeToString(pub) != c.pub {
			t.Fatalf("%s: pub %x", c.info, pub)
		}
		if got := Commitment(pub, salt); got != c.commitment {
			t.Fatalf("%s: commitment %s", c.info, got)
		}
	}
}
