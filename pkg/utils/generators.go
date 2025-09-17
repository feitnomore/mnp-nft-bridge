/**
 * Copyright 2025 Marcelo Parisi (github.com/feitnomore)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/google/nftables"
	"k8s.io/klog/v2"
)

const (
	TCPPrefix          = "TCP"
	UDPPrefix          = "UDP"
	HWPrefix           = "HW"
	HEXPrefix          = "0x"
	Uint32Size         = 4
	TruncatedHashBytes = 6 /* Used for GenerateHash */
)

/* Generates a SHA256 Hash (truncado para hexadecimal) */
func GenerateHash(inputStr string) string {
	thisHash := sha256.Sum256([]byte(inputStr))
	/* Use the first TruncatedHashBytes of the hash for the hexadecimal representation */
	hexHash := hex.EncodeToString(thisHash[:TruncatedHashBytes])
	return hexHash
}

/* Generate Random UINT32 */
func GenerateRandUInt32() uint32 {
	var randomUint32 uint32
	buf := make([]byte, Uint32Size)
	_, err := rand.Read(buf)
	if err != nil {
		klog.Errorf("Failed to generate random bytes for uint32: %v", err)
		return 0
	}
	randomUint32 = binary.LittleEndian.Uint32(buf)
	return randomUint32
}

/* Creates a random short ID for logging */
func GenerateRandomShortID() string {
	/* Generates a random number between 0 and 999999 */
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		klog.Warningf("Failed to generate random int for short ID, using fallback: %v", err)
		/* Fallback to a less random ID on error */
		return fmt.Sprintf("%06x", GenerateRandUInt32()%0xffffff)
	}
	return fmt.Sprintf("%06d", n) /* Format with leading zeros to have 6 digits */
}

func GenerateRuleID(rule *nftables.Rule) string {
	ruleBytes, err := json.Marshal(rule.Exprs)
	if err != nil {
		/* In case of serialization error, log and return an error ID or panic. */
		klog.Errorf("Failed to marshal rule expressions for ID generation: %v", err)
		return "errorGeneratingRuleID"
	}
	hash := sha256.Sum256(ruleBytes)
	return hex.EncodeToString(hash[:])
}

/* Creates a stable ID for an nftables set based on its context */
func GenerateDeterministicSetID(chainSuffix, ruleDirection string, ruleIndex int, setType string) string {
	identifierString := fmt.Sprintf("chainSuffix:%s_dir:%s_idx:%d_type:%s",
		chainSuffix,
		ruleDirection,
		ruleIndex,
		setType,
	)
	hash := sha256.Sum256([]byte(identifierString))
	return hex.EncodeToString(hash[:]) /* Returns the full hash for greater uniqueness */
}

func ParseUint32FromHex(hexStr string) uint32 {
	if len(hexStr) == 0 {
		return 0
	}

	trimmedHexStr := strings.TrimPrefix(hexStr, HEXPrefix)
	if len(trimmedHexStr) == 0 {
		return 0
	}

	/* Ensure the hexadecimal string isn't too long for a uint32 (maximum 8 hex characters).
	 * Grab the last 8 characters if it's longer, since the set ID is usually a smaller value.
	 */
	if len(trimmedHexStr) > 8 {
		trimmedHexStr = trimmedHexStr[:8]
	}

	/* hex.DecodeString requires an even number of characters.
	 * Add a leading '0' if the string has an odd length.
	 */
	if len(trimmedHexStr)%2 != 0 {
		trimmedHexStr = "0" + trimmedHexStr
	}

	/* If after padding it is still empty or too long (should not happen with initial truncation) */
	if len(trimmedHexStr) == 0 || len(trimmedHexStr) > 8 {
		klog.Warningf("ParseUint32FromHex: Invalid length for hex string '%s' (original '%s') after processing, returning 0", trimmedHexStr, hexStr)
		return 0
	}

	decoded, err := hex.DecodeString(trimmedHexStr)
	if err != nil {
		klog.Warningf("ParseUint32FromHex: Error decoding hex string '%s' (original '%s') to bytes: %v, returning 0", trimmedHexStr, hexStr, err)
		return 0
	}

	if len(decoded) == 0 {
		klog.Warningf("ParseUint32FromHex: Decoded hex string '%s' (original '%s') resulted in empty byte slice, returning 0", trimmedHexStr, hexStr)
		return 0
	}

	/* Create a 4-byte slice and copy the decoded bytes to the rightmost part (BigEndian). */
	finalBytes := make([]byte, Uint32Size)
	copy(finalBytes[Uint32Size-len(decoded):], decoded)

	return binary.BigEndian.Uint32(finalBytes)
}
