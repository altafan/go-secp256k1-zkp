package secp256k1

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContextCreate(t *testing.T) {

	params := uint(ContextSign | ContextVerify)
	ctx, err := ContextCreate(params)

	assert.NoError(t, err)
	assert.NotNil(t, ctx)
	assert.IsType(t, Context{}, *ctx)

	clone, err := ContextClone(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, ctx)
	assert.IsType(t, Context{}, *ctx)

	ContextDestroy(clone)

	res := ContextRandomize(ctx, testingRand32())
	assert.Equal(t, 1, res)

	ContextDestroy(ctx)
}

func TestECPrivKeyTweakAdd(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/ecprivkey.json")
	if err != nil {
		t.Fatal(err)
	}

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["tweakAdd"].([]interface{})

	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		key, _ := hex.DecodeString(v["key"].(string))
		scalar, _ := hex.DecodeString(v["scalar"].(string))
		res, ok := ECPrivKeyTweakAdd(ctx, key, scalar)
		assert.Equal(t, true, ok)
		assert.Equal(
			t,
			v["expected"].(string),
			hex.EncodeToString(res),
		)
	}
}

func TestECPrivKeyTweakMul(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/ecprivkey.json")
	if err != nil {
		t.Fatal(err)
	}

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["tweakMul"].([]interface{})

	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})
		key, _ := hex.DecodeString(v["key"].(string))
		scalar, _ := hex.DecodeString(v["scalar"].(string))
		res, ok := ECPrivKeyTweakMul(ctx, key, scalar)
		assert.Equal(t, true, ok)
		assert.Equal(
			t,
			v["expected"].(string),
			hex.EncodeToString(res),
		)
	}
}

func testingRand32() [32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return key
}
