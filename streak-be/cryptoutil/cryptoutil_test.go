package cryptoutil_test

import (
	"testing"
	"time"

	"github.com/rohitxdev/go-api-starter/cryptoutil"
	"github.com/stretchr/testify/assert"
)

func TestCryptoUtil(t *testing.T) {
	t.Run("AES encryption & decryption", func(t *testing.T) {
		t.Parallel()
		key := []byte("secretkey")
		plainText := []byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit. Iusto itaque error, voluptates molestiae at consequuntur minima, doloremque consequatur dolores ipsam voluptatem quaerat aliquid, adipisci rem est quia nobis ducimus neque distinctio debitis. Quo exercitationem earum, possimus velit non ullam tempora, architecto maxime rerum accusantium aliquam. Fugit laborum omnis non distinctio.")

		encryptedData, err := cryptoutil.EncryptAES(plainText, key)
		assert.NoError(t, err)

		decryptedData, err := cryptoutil.DecryptAES(encryptedData, key)
		assert.NoError(t, err)

		assert.Equal(t, plainText, decryptedData)
	})

	t.Run("Secure hashing & verification", func(t *testing.T) {
		t.Parallel()
		password := "password"
		hash, err := cryptoutil.HashSecure(password)
		assert.NoError(t, err)
		assert.NotEmpty(t, hash)

		assert.True(t, cryptoutil.VerifyHashSecure(password, hash))
		assert.False(t, cryptoutil.VerifyHashSecure("wrong-password", hash))
	})

	t.Run("JWT generation & verification", func(t *testing.T) {
		t.Parallel()
		secret := "secret"

		t.Run("Invalid token", func(t *testing.T) {
			t.Parallel()
			_, err := cryptoutil.VerifyJWT[int]("invalid-token", secret)
			assert.Error(t, err)
		})

		t.Run("Expired token", func(t *testing.T) {
			t.Parallel()
			token, err := cryptoutil.GenerateJWT(1, -time.Second, secret)
			assert.NoError(t, err)
			assert.NotEmpty(t, token)

			_, err = cryptoutil.VerifyJWT[int](token, secret)
			assert.Error(t, err)
		})

		t.Run("Unexpired token", func(t *testing.T) {
			t.Parallel()
			token, err := cryptoutil.GenerateJWT(1, time.Second, secret)
			assert.NoError(t, err)
			assert.NotEmpty(t, token)

			_, err = cryptoutil.VerifyJWT[int](token, secret)
			assert.NoError(t, err)
		})

		t.Run("Int", func(t *testing.T) {
			t.Parallel()
			token, err := cryptoutil.GenerateJWT(1, time.Second*10, secret)
			assert.NoError(t, err)
			assert.NotEmpty(t, token)

			_, err = cryptoutil.VerifyJWT[int](token, secret)
			assert.NoError(t, err)
		})

		t.Run("String", func(t *testing.T) {
			t.Parallel()
			token, err := cryptoutil.GenerateJWT("hello", time.Second*10, secret)
			assert.NoError(t, err)
			assert.NotEmpty(t, token)

			_, err = cryptoutil.VerifyJWT[string](token, secret)
			assert.NoError(t, err)
		})

		t.Run("Map", func(t *testing.T) {
			t.Parallel()
			token, err := cryptoutil.GenerateJWT(map[string]string{"key": "value"}, time.Second*10, secret)
			assert.NoError(t, err)
			assert.NotEmpty(t, token)

			_, err = cryptoutil.VerifyJWT[map[string]string](token, secret)
			assert.NoError(t, err)
		})
	})
}
