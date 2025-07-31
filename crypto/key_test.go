package crypto

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
)

const (
	mnemonic                     = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title"
	masterKeyWithoutPassphrase   = "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620"
	masterKeyWithPassphrase      = "70531039904019351e1afb361cd1b312a4d0565d4ff9f8062d38acf4b15cce41d7b5738d9c893feea55512a3004acb0d222c35d3e3d5cde943a15a9824cbac59443cf67e589614076ba01e354b1a432e0e6db3b59e37fc56b5fb0222970a010e"
	masterXprivWithoutPassphrase = "root_xsk1cpj6l55r9nvtpp7ymx4hqy05s8hpupepu782thtqnuat8u2k6fzaza4a3l2wcc95wvwrjx9z5u4qyfkqe5geas6mgljd2kyyvel4223r7l7u6jsscmxjcuun43sasau88cjg7stkxj4rmqf27vnll6wkyqya0lre"
	masterXprivWithPassphrase    = "root_xsk1wpf3qwvsgqvn28s6lvmpe5dnz2jdq4jaflulsp3d8zk0fv2ueeqa0dtn3kwgj0lw54239gcqft9s6g3vxhf784wda9p6zk5cyn96ck2y8nm8ukykzsrkhgq7x4935sewpekm8dv7xl79dd0mqg3fwzsppc0a620w"
	xpubWithoutPassphrase        = "root_xvk1w4lf24u8nrhhxwke803j97cyxpfa266yt5l72q4u7l9556c0p34z8alae49pp3kd93ee8trpmpmcw03y3aqhvd928kqj4ue8ll5avgqf6tjem"
	xpubWithPassphrase           = "root_xvk1qmg8jpjyyqt43npkkf6sc5m5t4yn69kn907pefgesj8xu8jxczlyg08k0evfv9q8dwspud2trfpjurndkw6eudlu266lkq3zju9qzrsrvu0hy"
	passphrase                   = "foo"
	seedWithoutPassphrase        = "c465afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d225d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620"
	seedWithPassphrase           = "70531039904019351e1afb361cd1b312a4d0565d4ff9f8062d38acf4b15cce81d7b5738d9c893feea55512a3004acb0d222c35d3e3d5cde943a15a9824cbac59443cf67e589614076ba01e354b1a432e0e6db3b59e37fc56b5fb0222970a010e"
)

func TestExtendedSigningKeyWithoutPassphrase(t *testing.T) {
	entropy, _ := bip39.EntropyFromMnemonic(mnemonic)

	seed := pbkdf2.Key([]byte{}, entropy, 4096, 96, sha512.New)
	seedStr := hex.EncodeToString(seed)
	if seedStr != seedWithoutPassphrase {
		t.Errorf("invalid seed\ngot: %s\nwant: %s\n", seedStr, seedWithoutPassphrase)
	}

	got := NewXPrvKeyFromEntropy(entropy, "")
	want, _ := hex.DecodeString(masterKeyWithoutPassphrase)

	if !bytes.Equal(got, want) {
		t.Errorf("invalid master key\ngot: %x\nwant: %x\n", got, want)
	}

	mXpriv := got.Bech32("root_xsk")
	if mXpriv != masterXprivWithoutPassphrase {
		t.Errorf("invalid master key bech32\ngot: %s\nwant: %s\n", mXpriv, masterXprivWithoutPassphrase)
	}
	mXpub := got.XPubKey().Bech32("root_xvk")
	if mXpub != xpubWithoutPassphrase {
		t.Errorf("invalid xpub key bech32\ngot: %s\nwant: %s\n", mXpub, xpubWithoutPassphrase)
	}
}

func TestExtendedSigningKeyWithPassphrase(t *testing.T) {
	entropy, _ := bip39.EntropyFromMnemonic(mnemonic)

	seed := pbkdf2.Key([]byte(passphrase), entropy, 4096, 96, sha512.New)
	seedStr := hex.EncodeToString(seed)
	if seedStr != seedWithPassphrase {
		t.Errorf("invalid seed\ngot: %s\nwant: %s\n", seedStr, seedWithPassphrase)
	}

	got := NewXPrvKeyFromEntropy(entropy, passphrase)
	want, _ := hex.DecodeString(masterKeyWithPassphrase)

	if !bytes.Equal(got, want) {
		t.Errorf("invalid master key\ngot: %x\nwant: %x\n", got, want)
	}

	mXpriv := got.Bech32("root_xsk")
	if mXpriv != masterXprivWithPassphrase {
		t.Errorf("invalid master key bech32\ngot: %s\nwant: %s\n", mXpriv, masterXprivWithPassphrase)
	}
	mXpub := got.XPubKey().Bech32("root_xvk")
	if mXpub != xpubWithPassphrase {
		t.Errorf("invalid xpub key bech32\ngot: %s\nwant: %s\n", mXpub, xpubWithPassphrase)
	}
}

func TestExtendedSigningKeyWithSeed(t *testing.T) {
	seedBytes1, _ := hex.DecodeString(seedWithoutPassphrase)
	got := NewXPrvKeyFromSeed(seedBytes1)
	want, _ := hex.DecodeString(masterKeyWithoutPassphrase)
	if !bytes.Equal(got, want) {
		t.Errorf("invalid master key\ngot: %x\nwant: %x\n", got, want)
	}

	seedBytes2, _ := hex.DecodeString(seedWithPassphrase)
	got = NewXPrvKeyFromSeed(seedBytes2)
	want, _ = hex.DecodeString(masterKeyWithPassphrase)
	if !bytes.Equal(got, want) {
		t.Errorf("invalid master key\ngot: %x\nwant: %x\n", got, want)
	}
}
