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
		fixedInputTags := []*FixedAssetTag{}
		for _, inTag := range v["inputTags"].([]interface{}) {
			fixedAssetTag, err := FixedAssetTagFromHex(inTag.(string))
			assert.NoError(t, err)
			fixedInputTags = append(fixedInputTags, fixedAssetTag)
		}

		proof, inputIndex, err := SurjectionProofInitialize(
			ctx,
			fixedInputTags,
			nInputTagsToUse,
			fixedOutputTag,
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
		ephemeralInTags := []*Generator{}
		for _, inTag := range v["ephemeralInputTags"].([]interface{}) {
			ephemeralInTag, err := GeneratorFromString(inTag.(string))
			assert.NoError(t, err)
			ephemeralInTags = append(ephemeralInTags, ephemeralInTag)
		}

		err = SurjectionProofGenerate(
			ctx,
			proof,
			ephemeralInTags,
			ephemeralOutTag,
			inIndex,
			inBlindingKey,
			outBlindingKey,
		)
		assert.NoError(t, err)
		assert.NotNil(t, proof)
		assert.Equal(t, v["expected"].(string), proof.String())
		assert.Equal(t, true, SurjectionProofVerify(ctx, proof, ephemeralInTags, ephemeralOutTag))
	}
}

func TestMaybeValidProof(t *testing.T) {
	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	outputAssets := [][]byte{
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
	}
	outputBfs := [][]byte{
		h2b("06f82730207a7d18f56b67b8232a2183afec39080369b32b83e276017359c329"),
		h2b("06f82730207a7d18f56b67b8232a2183afec39080369b32b83e276017359c329"),
		h2b("b919547b0fe215b1cc259f97ae435d6140d6d68ab62b6ceae216af48a75ed8dd"),
	}

	inputAssets := [][]byte{
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
		h2b("ed167d1b67cf8c72fdc105e7499003a06745e2c42c7d32ed33d3c6dae06a96dd"),
	}
	inputAbfs := [][]byte{
		h2b("11a0828ded4fa0ebcffced49d7e8118ceba3484363486d43ce04fbbb756dfbf9"),
		h2b("25dde14dd92c0594a3765667ad0ba3263298426e5c5cf38148587a9cd3b2f936"),
	}

	proofs := []string{
		"0200033e70e62dc661225a43f244ac54110cf68a855544be210442ca47e91e5580705dc0955a93a957f4a336cfec7df190c7df0c84fe86f31b51cae3ea1877304cd5a85d516a4e921dd3645783cd41fca8d519783a57dc14767946af0d4fa223d65392",
		"0200033e70e62dc661225a43f244ac54110cf68a855544be210442ca47e91e5580705dc0955a93a957f4a336cfec7df190c7df0c84fe86f31b51cae3ea1877304cd5a85d516a4e921dd3645783cd41fca8d519783a57dc14767946af0d4fa223d65392",
		"0200033e8c1bb14b8bb3163102181b7f932515dad5e5ec02e6d32180c04aad77ec8f0ea12653e52cfc8f6d7854c3d671dda156a2dffa750a08f7c4a04b4644559879a46be28a1aa499f8b9068326f3a0bf764b4a8cb67d80f60d0d856118170e5787b4",
	}

	for j := 0; j < 100; j++ {
		ress := make([]bool, 0, len(proofs))
		for i, outputAsset := range outputAssets {
			outputBf := outputBfs[i]

			outputGenerator, err := GeneratorGenerateBlinded(ctx, outputAsset, outputBf)
			if err != nil {
				t.Fatal(err)
			}

			inputGenerators := make([]*Generator, 0, len(inputAssets))
			for i, v := range inputAssets {
				gen, err := GeneratorGenerateBlinded(ctx, v, inputAbfs[i])
				if err != nil {
					t.Fatal(err)
				}
				inputGenerators = append(inputGenerators, gen)
			}

			proof, err := SurjectionProofFromString(proofs[i])
			if err != nil {
				t.Fatal(err)
			}
			res := SurjectionProofVerify(ctx, proof, inputGenerators, outputGenerator)
			ress = append(ress, res)
		}
		fmt.Println(ress)
	}
}

func h2b(str string) []byte {
	buf, _ := hex.DecodeString(str)
	return buf
}
