package secp256k1

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSurjectionProofInitializeAndSerialize(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/surjectionproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["initializeAndSerialize"].([]interface{})

	ctx, _ := ContextCreate(ContextNone)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		seed, _ := hex.DecodeString(v["seed"].(string))
		nInputTagsToUse := int(v["inputTagsToUse"].(float64))
		nMaxIterations := int(v["maxIterations"].(float64))
		fixedOutputTag, err := FixedAssetTagFromHex(v["outputTag"].(string))
		assert.NoError(t, err)
		fixedInputTags := []FixedAssetTag{}
		for _, inTag := range v["inputTags"].([]interface{}) {
			fixedAssetTag, err := FixedAssetTagFromHex(inTag.(string))
			assert.NoError(t, err)
			fixedInputTags = append(fixedInputTags, *fixedAssetTag)
		}

		proof, inputIndex, err := SurjectionProofInitialize(
			ctx,
			fixedInputTags,
			nInputTagsToUse,
			*fixedOutputTag,
			nMaxIterations,
			seed,
		)
		assert.NoError(t, err)
		expected := v["expected"].(map[string]interface{})
		assert.Equal(t, int(expected["inputIndex"].(float64)), inputIndex)
		assert.Equal(t, expected["proof"].(string), proof.String())
		assert.Equal(t, int(expected["nInputs"].(float64)), SurjectionProofNTotalInputs(ctx, proof))
		assert.Equal(t, int(expected["nUsedInputs"].(float64)), SurjectionProofNUsedInputs(ctx, proof))
	}
}

func TestSurjectionProofGenerateAndVerify(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/surjectionproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["generateAndVerify"].([]interface{})

	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		inIndex := int(v["inputIndex"].(float64))
		inBlindingKey, _ := hex.DecodeString(v["inputBlindingKey"].(string))
		outBlindingKey, _ := hex.DecodeString(v["outputBlindingKey"].(string))
		proof, err := SurjectionProofFromString(v["proof"].(string))
		assert.NoError(t, err)
		ephemeralOutTag, err := GeneratorFromString(v["ephemeralOutputTag"].(string))
		assert.NoError(t, err)
		ephemeralInTags := []Generator{}
		for _, inTag := range v["ephemeralInputTags"].([]interface{}) {
			ephemeralInTag, err := GeneratorFromString(inTag.(string))
			assert.NoError(t, err)
			ephemeralInTags = append(ephemeralInTags, *ephemeralInTag)
		}

		err = SurjectionProofGenerate(
			ctx,
			proof,
			ephemeralInTags,
			*ephemeralOutTag,
			inIndex,
			inBlindingKey,
			outBlindingKey,
		)
		assert.NoError(t, err)
		assert.NotNil(t, proof)
		assert.Equal(t, v["expected"].(string), proof.String())
		assert.Equal(t, true, SurjectionProofVerify(ctx, proof, ephemeralInTags, *ephemeralOutTag))
	}
}

func TestMaybeInvalidProof(t *testing.T) {
	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	outputAsset := h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a")
	outputBf := h2b("24462ea36908c31d4f6c1096b442623ee27677ed9bae5f8614b5f4e0fca334d3")

	outputGenerator, err := GeneratorGenerateBlinded(ctx, outputAsset, outputBf)
	if err != nil {
		t.Fatal(err)
	}

	inputGenerators := make([]Generator, 0)
	inputAssets := [][]byte{
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
		h2b("a613c0dada8dfe29e2e135ef6ce15ae049c84cbc723f702148e9c01b965d5dbc"),
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
	}
	inputAbfs := [][]byte{
		h2b("25e369cb9e734d7065f47097a89f923342d986c4456c1525d91d62620b17b842"),
		h2b("37e1ae117f13f3a51d7ff407caf3b9b53bd2ee86817e72924fb6ca8cb1f345ef"),
		h2b("e5c31bf5f833d5a5cbab21e16a618bf1572481d4bad51754ec12cdd605ae2935"),
	}
	for i, v := range inputAssets {
		gen, err := GeneratorGenerateBlinded(ctx, v, inputAbfs[i])
		if err != nil {
			t.Fatal(err)
		}
		inputGenerators = append(inputGenerators, *gen)
	}

	proof, err := SurjectionProofFromString("030007087cb161d9db297f23da2ed4a2db7e9e7f7d31f456925e2d0959a5668cf964356495f703ad1af43cd464099e8134e22defcf64a0d9606895d32aded361e28f39de0da014114c0d89d52049253f1bf182f578679dbb388603afa708fee3bee8977031053a134a57de57f66ae51b70e1f153cc13c47a75c2ad0afd313cea1e7402")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(SurjectionProofVerify(ctx, proof, inputGenerators, *outputGenerator))
}

func TestMaybeValidProof(t *testing.T) {
	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	outputAsset := h2b("a613c0dada8dfe29e2e135ef6ce15ae049c84cbc723f702148e9c01b965d5dbc")
	outputBf := h2b("202c99a516a7188db0d56a713ede15c6527daff3094acdfbaf8b46556d27b205")

	outputGenerator, err := GeneratorGenerateBlinded(ctx, outputAsset, outputBf)
	if err != nil {
		t.Fatal(err)
	}

	inputGenerators := make([]Generator, 0)
	inputAssets := [][]byte{
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
		h2b("a613c0dada8dfe29e2e135ef6ce15ae049c84cbc723f702148e9c01b965d5dbc"),
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
	}
	inputAbfs := [][]byte{
		h2b("25e369cb9e734d7065f47097a89f923342d986c4456c1525d91d62620b17b842"),
		h2b("37e1ae117f13f3a51d7ff407caf3b9b53bd2ee86817e72924fb6ca8cb1f345ef"),
		h2b("e5c31bf5f833d5a5cbab21e16a618bf1572481d4bad51754ec12cdd605ae2935"),
	}
	for i, v := range inputAssets {
		gen, err := GeneratorGenerateBlinded(ctx, v, inputAbfs[i])
		if err != nil {
			t.Fatal(err)
		}
		inputGenerators = append(inputGenerators, *gen)
	}

	proof, err := SurjectionProofFromString("030007a435a8a2ca2ea9693c8ec6b6977b35282e93ff34a0733fad8e4712783caf6bbd8dad5297a45b23f807ee0ff588b3914383508e6e44aeffc019b0b6c96bca547b8689853f4648f1559423bfbb3d03df199617332b28739d55e190ca82406270ec444dcda442cd9cdae5d033c4a5d3373583c3cb9c4a60fff4a7cdff79874d5146")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(SurjectionProofVerify(ctx, proof, inputGenerators, *outputGenerator))
}

func h2b(str string) []byte {
	buf, _ := hex.DecodeString(str)
	return buf
}
