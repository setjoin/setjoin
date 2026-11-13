package cryptokey

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/sm4"
)

func init() {
	newSM4Block = func(key []byte) (cipher.Block, error) {
		return sm4.NewCipher(key)
	}
}
