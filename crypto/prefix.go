package crypto

import "strings"

type KeyPrefixType int

const (
	KeyPrefixTypePrivateKey KeyPrefixType = iota
	KeyPrefixTypePublicKey
	KeyPrefixTypeExtendedPrivateKey
	KeyPrefixTypeExtendedPublicKey
)

type KeyPrefix struct {
	Name                     string
	PrivateKeyPrefix         string
	PublicKeyPrefix          string
	ExtendedPrivateKeyPrefix string
	ExtendedPublicKeyPrefix  string
}

func GetKeyPrefixByXpriv(xpriv string) (ret KeyPrefix, exist bool) {
	arr := strings.Split(xpriv, "1")
	if len(arr) <= 1 || arr[0] == "" {
		return ret, false
	}
	return GetKeyPrefix(KeyPrefixTypeExtendedPrivateKey, arr[0])
}

func GetKeyPrefixByXpub(xpub string) (ret KeyPrefix, exist bool) {
	arr := strings.Split(xpub, "1")
	if len(arr) <= 1 || arr[0] == "" {
		return ret, false
	}
	return GetKeyPrefix(KeyPrefixTypeExtendedPublicKey, arr[0])
}

func GetKeyPrefix(prefixType KeyPrefixType, prefix string) (ret KeyPrefix, exist bool) {
	var checkFn func(keyPrefix *KeyPrefix) bool
	switch prefixType {
	case KeyPrefixTypePrivateKey:
		checkFn = func(keyPrefix *KeyPrefix) bool { return prefix == keyPrefix.PrivateKeyPrefix }
	case KeyPrefixTypePublicKey:
		checkFn = func(keyPrefix *KeyPrefix) bool { return prefix == keyPrefix.PublicKeyPrefix }
	case KeyPrefixTypeExtendedPrivateKey:
		checkFn = func(keyPrefix *KeyPrefix) bool { return prefix == keyPrefix.ExtendedPrivateKeyPrefix }
	case KeyPrefixTypeExtendedPublicKey:
		checkFn = func(keyPrefix *KeyPrefix) bool { return prefix == keyPrefix.ExtendedPublicKeyPrefix }
	default:
		return ret, false
	}
	for _, keyPrefix := range KeyPrefixes {
		if checkFn(&keyPrefix) {
			return keyPrefix, true
		}
	}
	return ret, false
}

// KeyPrefixes is prefix list by https://cips.cardano.org/cip/CIP-5
var KeyPrefixes = []KeyPrefix{
	{
		Name:                     "CIP-1852's root",
		PrivateKeyPrefix:         "root_sk",
		PublicKeyPrefix:          "root_vk",
		ExtendedPrivateKeyPrefix: "root_xsk",
		ExtendedPublicKeyPrefix:  "root_xvk",
	},
	{
		Name:                     "CIP-1852's account",
		PrivateKeyPrefix:         "acct_sk",
		PublicKeyPrefix:          "acct_vk",
		ExtendedPrivateKeyPrefix: "acct_xsk",
		ExtendedPublicKeyPrefix:  "acct_xvk",
	},
	{
		Name:                     "CIP-1852's address signing/verification",
		PrivateKeyPrefix:         "addr_sk",
		PublicKeyPrefix:          "addr_vk",
		ExtendedPrivateKeyPrefix: "addr_xsk",
		ExtendedPublicKeyPrefix:  "addr_xvk",
	},
	{
		Name:                     "CIP-1852’s constitutional committee cold signing/verification",
		PrivateKeyPrefix:         "cc_cold_sk",
		PublicKeyPrefix:          "cc_cold_vk",
		ExtendedPrivateKeyPrefix: "cc_cold_xsk",
		ExtendedPublicKeyPrefix:  "cc_cold_xvk",
	},
	{
		Name:                     "CIP-1852’s constitutional committee hot signing/verification",
		PrivateKeyPrefix:         "cc_hot_sk",
		PublicKeyPrefix:          "cc_hot_vk",
		ExtendedPrivateKeyPrefix: "cc_hot_xsk",
		ExtendedPublicKeyPrefix:  "cc_hot_xvk",
	},
	{
		Name:                     "CIP-1852’s DRep signing/verification",
		PrivateKeyPrefix:         "drep_sk",
		PublicKeyPrefix:          "drep_vk",
		ExtendedPrivateKeyPrefix: "drep_xsk",
		ExtendedPublicKeyPrefix:  "drep_xvk",
	},
	{
		Name:                     "CIP-1852's stake address",
		PrivateKeyPrefix:         "stake_sk",
		PublicKeyPrefix:          "stake_vk",
		ExtendedPrivateKeyPrefix: "stake_xsk",
		ExtendedPublicKeyPrefix:  "stake_xvk",
	},
	{
		Name:                     "CIP-1854's root",
		PrivateKeyPrefix:         "root_shared_sk",
		PublicKeyPrefix:          "root_shared_vk",
		ExtendedPrivateKeyPrefix: "root_shared_xsk",
		ExtendedPublicKeyPrefix:  "root_shared_xvk",
	},
	{
		Name:                     "CIP-1854's account",
		PrivateKeyPrefix:         "acct_shared_sk",
		PublicKeyPrefix:          "acct_shared_vk",
		ExtendedPrivateKeyPrefix: "acct_shared_xsk",
		ExtendedPublicKeyPrefix:  "acct_shared_xvk",
	},
	{
		Name:                     "CIP-1854's address signing/verification",
		PrivateKeyPrefix:         "addr_shared_sk",
		PublicKeyPrefix:          "addr_shared_vk",
		ExtendedPrivateKeyPrefix: "addr_shared_xsk",
		ExtendedPublicKeyPrefix:  "addr_shared_xvk",
	},
	{
		Name:                     "CIP-1854's stake address",
		PrivateKeyPrefix:         "stake_shared_sk",
		PublicKeyPrefix:          "stake_shared_vk",
		ExtendedPrivateKeyPrefix: "stake_shared_xsk",
		ExtendedPublicKeyPrefix:  "stake_shared_xvk",
	},
	{
		Name:                     "Pool operator signing/verification",
		PrivateKeyPrefix:         "pool_sk",
		PublicKeyPrefix:          "pool_vk",
		ExtendedPrivateKeyPrefix: "pool_xsk",
		ExtendedPublicKeyPrefix:  "pool_xvk",
	},
	{
		Name:             "CIP-36's vote",
		PrivateKeyPrefix: "cvote_sk",
		PublicKeyPrefix:  "cvote_vk",
	},
	{
		Name:             "Genesis signing/verification",
		PrivateKeyPrefix: "gen_sk",
		PublicKeyPrefix:  "gen_vk",
	},
	{
		Name:             "Genesis delegate",
		PrivateKeyPrefix: "gen_deleg_sk",
		PublicKeyPrefix:  "gen_deleg_vk",
	},
	{
		Name:             "Genesis UTXO",
		PrivateKeyPrefix: "gen_utxo_sk",
		PublicKeyPrefix:  "gen_utxo_vk",
	},
	{
		Name:             "KES signing/verification",
		PrivateKeyPrefix: "kes_sk",
		PublicKeyPrefix:  "kes_vk",
	},
	{
		Name:             "CIP-1855's policy",
		PrivateKeyPrefix: "policy_sk",
		PublicKeyPrefix:  "policy_vk",
	},
	{
		Name:             "VRF signing/verification",
		PrivateKeyPrefix: "vrf_sk",
		PublicKeyPrefix:  "vrf_vk",
	},
}
