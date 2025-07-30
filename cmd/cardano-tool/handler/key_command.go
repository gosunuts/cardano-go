package handler

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cryptogarageinc/cardano-go"
	"github.com/cryptogarageinc/cardano-go/crypto"
	"github.com/cryptogarageinc/cardano-go/internal/bech32"
	"github.com/spf13/cobra"
)

type keyCmdHandler struct {
}

func NewKeyCmdHandler() *keyCmdHandler {
	return &keyCmdHandler{}
}

func (h *keyCmdHandler) Commands(ctx context.Context) []*cobra.Command {
	return []*cobra.Command{
		h.getXprivCmd(ctx),
		h.deriveCmd(ctx),
		h.dumpKeyCmd(ctx),
		h.getAddressWithKeyCmd(ctx),
		h.getAddressWithDeriveCmd(ctx),
		h.parseAddressCmd(ctx),
	}
}

func (h *keyCmdHandler) getXprivCmd(_ context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "xprivfromseed",
		Short: "get xpriv from seed",
		Long:  `Get a xpriv from seed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			seed, _ := cmd.Flags().GetString("seed")
			if seed == "" {
				err := errors.New("invalid request. seed is empty")
				return err
			}
			seedBytes, err := hex.DecodeString(seed)
			if err != nil {
				return err
			}
			xpriv := crypto.NewXPrvKeyFromSeed(seedBytes)
			fmt.Printf("xpriv: %s\n", xpriv.Bech32("root_xsk"))
			return nil
		},
	}

	cmd.Flags().StringP("seed", "s", "", "seed hex")
	cmd.Flags().Bool("testnet", false, "Use testnet network")
	return cmd
}

func (h *keyCmdHandler) deriveCmd(_ context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deriveKey",
		Short: "derive key",
		Long:  `derive extended privkey or extended pubkey.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			xpubStr, _ := cmd.Flags().GetString("xpub")
			if xpubStr == "" {
				err := errors.New("invalid request. xpub is empty")
				return err
			}
			prefixStr, _ := cmd.Flags().GetString("prefix")

			path, _ := cmd.Flags().GetString("path")
			indexes, err := parsePath(path)
			if err != nil {
				return err
			}

			prefix, ok := crypto.GetKeyPrefix(crypto.KeyPrefixTypeExtendedPrivateKey, prefixStr)
			if !ok {
				prefix, ok = crypto.GetKeyPrefix(crypto.KeyPrefixTypeExtendedPublicKey, prefixStr)
				if !ok {
					return errors.New("invalid request. unknown prefix")
				}
			}

			_, existXpriv := crypto.GetKeyPrefixByXpriv(xpubStr)
			if existXpriv {
				xpriv, err := crypto.NewXPrvKey(xpubStr)
				if err != nil {
					return err
				}
				for _, idx := range indexes {
					xpriv = xpriv.Derive(idx)
				}
				fmt.Printf("xpriv: %s\n", xpriv.Bech32(prefix.ExtendedPrivateKeyPrefix))
				fmt.Printf("xpub : %s\n", xpriv.XPubKey().Bech32(prefix.ExtendedPublicKeyPrefix))
			} else {
				xpub, err := crypto.NewXPubKey(xpubStr)
				if err != nil {
					return err
				}
				for _, idx := range indexes {
					xpub, err = xpub.Derive(idx)
					if err != nil {
						return err
					}
				}
				fmt.Printf("xpub : %s\n", xpub.Bech32(prefix.ExtendedPublicKeyPrefix))
			}
			return nil
		},
	}

	cmd.Flags().StringP("xpub", "k", "", "extended public key or extended private key")
	cmd.Flags().StringP("path", "p", "", "derive path (ex: 1852'/1815'/0'/0/0 )")
	cmd.Flags().StringP("prefix", "f", "", "output bech32 prefix")
	return cmd
}

func (h *keyCmdHandler) dumpKeyCmd(_ context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dumpkey",
		Short: "dump key",
		Long:  `cump extended privkey or extended pubkey.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			xpubStr, _ := cmd.Flags().GetString("xpub")
			if xpubStr == "" {
				err := errors.New("invalid request. xpub is empty")
				return err
			}
			_, existXpriv := crypto.GetKeyPrefixByXpriv(xpubStr)
			if existXpriv {
				xpriv, err := crypto.NewXPrvKey(xpubStr)
				if err != nil {
					return err
				}
				prefix, ok := crypto.GetKeyPrefixByXpriv(xpubStr)
				if !ok {
					return errors.New("invalid request. unknown xpriv prefix")
				}
				fmt.Printf("xpriv: %s\n", xpriv.Bech32(prefix.ExtendedPrivateKeyPrefix))
				fmt.Printf("xpub : %s\n", xpriv.XPubKey().Bech32(prefix.ExtendedPublicKeyPrefix))
				fmt.Printf("priv : %s\n", xpriv.PrvKey().Bech32(prefix.PrivateKeyPrefix))
				fmt.Printf("pub  : %s\n", xpriv.PrvKey().PubKey().Bech32(prefix.PublicKeyPrefix))
			} else {
				xpub, err := crypto.NewXPubKey(xpubStr)
				if err != nil {
					return err
				}
				prefix, ok := crypto.GetKeyPrefixByXpub(xpubStr)
				if !ok {
					return errors.New("invalid request. unknown xpriv prefix")
				}
				fmt.Printf("xpub : %s\n", xpub.Bech32(prefix.ExtendedPublicKeyPrefix))
				fmt.Printf("pub  : %s\n", xpub.PubKey().Bech32(prefix.PublicKeyPrefix))
			}
			return nil
		},
	}

	cmd.Flags().StringP("xpub", "k", "", "extended public key or extended private key")
	return cmd
}

func (h *keyCmdHandler) getAddressWithKeyCmd(_ context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "addrWithKey",
		Short: "get address with key",
		Long:  `Get address with key.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			useTestnet, _ := cmd.Flags().GetBool("testnet")
			network := cardano.Mainnet
			if useTestnet {
				network = cardano.Testnet
			}

			keyStr, _ := cmd.Flags().GetString("key")
			stakeKeyStr, _ := cmd.Flags().GetString("stakeKey")
			if keyStr == "" && stakeKeyStr == "" {
				err := errors.New("invalid request. xpub is empty")
				return err
			}

			var paymentCred, stakeCred cardano.StakeCredential
			var err error
			if keyStr != "" {
				vk, err := getPubkeyByStr(keyStr)
				if err != nil {
					return err
				}
				paymentCred, err = cardano.NewKeyCredential(vk)
				if err != nil {
					return err
				}
			}
			if stakeKeyStr != "" {
				vk, err := getPubkeyByStr(stakeKeyStr)
				if err != nil {
					return err
				}
				stakeCred, err = cardano.NewKeyCredential(vk)
				if err != nil {
					return err
				}
			}

			var addr cardano.Address
			switch {
			case stakeKeyStr == "":
				addr, err = cardano.NewEnterpriseAddress(network, paymentCred)
			case keyStr == "":
				addr, err = cardano.NewStakeAddress(network, stakeCred)
			default:
				addr, err = cardano.NewBaseAddress(network, paymentCred, stakeCred)
			}
			if err != nil {
				return err
			}

			fmt.Printf("address: %s\n", addr.Bech32())
			return nil
		},
	}

	cmd.Flags().StringP("key", "k", "", "public key, or private key. hex or bech32")
	cmd.Flags().StringP("stakeKey", "s", "", "stake public key, or private key. hex or bech32")
	cmd.Flags().Bool("testnet", false, "Use testnet network")
	return cmd
}

func (h *keyCmdHandler) getAddressWithDeriveCmd(_ context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "addrWithDerive",
		Short: "get address with derive",
		Long:  `Get address with derive.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			useTestnet, _ := cmd.Flags().GetBool("testnet")
			network := cardano.Mainnet
			if useTestnet {
				network = cardano.Testnet
			}

			xpubStr, _ := cmd.Flags().GetString("xpub")
			if xpubStr == "" {
				err := errors.New("invalid request. xpub is empty")
				return err
			}
			addrIdx, _ := cmd.Flags().GetInt32("index")
			if addrIdx < 0 {
				err := errors.New("invalid request. addrIdx is under zero")
				return err
			}
			stakeIdx, _ := cmd.Flags().GetInt32("stakeindex")
			if stakeIdx < 0 {
				stakeIdx = addrIdx
			}

			xpubKey, err := getXpub(xpubStr)
			if err != nil {
				return err
			}

			chainRoleXpub, err := xpubKey.Derive(cardano.ExternalChainRole)
			if err != nil {
				return err
			}
			addrXpub, err := chainRoleXpub.Derive(uint32(addrIdx))
			if err != nil {
				return err
			}
			stakeRoleXpub, err := xpubKey.Derive(cardano.StakingRole)
			if err != nil {
				return err
			}
			stakeXpub, err := stakeRoleXpub.Derive(uint32(stakeIdx))
			if err != nil {
				return err
			}

			paymentCred, err := cardano.NewKeyCredential(addrXpub.PubKey())
			if err != nil {
				return err
			}
			stakeCred, err := cardano.NewKeyCredential(stakeXpub.PubKey())
			if err != nil {
				return err
			}
			addr, err := cardano.NewBaseAddress(network, paymentCred, stakeCred)
			if err != nil {
				return err
			}

			fmt.Printf("address: %s\n", addr.Bech32())
			return nil
		},
	}

	cmd.Flags().StringP("xpub", "k", "", "extended public key for account")
	cmd.Flags().Int32P("index", "i", 0, "bip32 address index")
	cmd.Flags().Int32P("stakeindex", "s", 0, "bip32 address index for stake")
	cmd.Flags().Bool("testnet", false, "Use testnet network")
	return cmd
}

func (h *keyCmdHandler) parseAddressCmd(_ context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parseAddr",
		Short: "parse address",
		Long:  `parse address.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			addrStr, _ := cmd.Flags().GetString("address")
			if addrStr == "" {
				err := errors.New("invalid request. address is empty")
				return err
			}

			addr, err := cardano.NewAddress(addrStr)
			if err != nil {
				return err
			}

			fmt.Printf("Network: %s\n", addr.Network.String())
			fmt.Printf("Type   : %d\n", addr.Type)
			switch addr.Type {
			case cardano.Base, cardano.Base + 1, cardano.Base + 2, cardano.Base + 3:
				if addr.Type&0x01 == 0 {
					dumpPaymentKey(&addr)
				} else {
					dumpPaymentScript(&addr)
				}
				if addr.Type&0x02 == 0 {
					dumpStakeKey(&addr)
				} else {
					dumpStakeScript(&addr)
				}
			case cardano.Ptr, cardano.Ptr + 1:
				fmt.Printf("CertIndex: %d\n", addr.Pointer.CertIndex)
				fmt.Printf("Slot     : %d\n", addr.Pointer.Slot)
				fmt.Printf("TxIndex  : %d\n", addr.Pointer.TxIndex)
				if addr.Type == cardano.Ptr {
					dumpPaymentKey(&addr)
				} else {
					dumpPaymentScript(&addr)
				}

			case cardano.Enterprise, cardano.Enterprise + 1:
				if addr.Type == cardano.Enterprise {
					dumpPaymentKey(&addr)
				} else {
					dumpPaymentScript(&addr)
				}
			case cardano.Stake, cardano.Stake + 1:
				if addr.Type == cardano.Stake {
					dumpStakeKey(&addr)
				} else {
					dumpStakeScript(&addr)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringP("address", "a", "", "address")
	return cmd
}

func getXpub(xpubStr string) (crypto.XPubKey, error) {
	var xpubKey crypto.XPubKey
	_, existXpriv := crypto.GetKeyPrefixByXpriv(xpubStr)
	if existXpriv {
		xpriv, err := crypto.NewXPrvKey(xpubStr)
		if err != nil {
			return xpubKey, err
		}
		xpubKey = xpriv.XPubKey()
	} else {
		xpub, err := crypto.NewXPubKey(xpubStr)
		if err != nil {
			return xpubKey, err
		}
		xpubKey = xpub
	}
	return xpubKey, nil
}

func parsePath(path string) ([]uint32, error) {
	paths := strings.Split(path, "/")
	indexes := make([]uint32, 0, len(paths))
	for _, item := range paths {
		if strings.EqualFold(item, "m") {
			continue
		}
		num := item
		isHardened := false
		if strings.HasSuffix(item, "h") ||
			strings.HasSuffix(item, "H") ||
			strings.HasSuffix(item, "'") {
			isHardened = true
			num = item[:len(item)-1]
		}
		idx64, err := strconv.ParseUint(num, 10, 32)
		if err != nil {
			return nil, err
		}
		idx := uint32(idx64)
		if isHardened {
			idx |= cardano.Hardened
		}
		indexes = append(indexes, idx)
	}
	return indexes, nil
}

func getPubkeyByStr(keyStr string) (crypto.PubKey, error) {
	_, keyBytes, err := bech32.DecodeToBase256(keyStr)
	if err != nil {
		keyBytes, err = hex.DecodeString(keyStr)
		if err != nil {
			return nil, err
		}
	}
	if len(keyBytes) > 32 {
		// private key
		sk := crypto.PrvKey(keyBytes)
		return sk.PubKey(), nil
	}
	return crypto.PubKey(keyBytes), nil
}

func dumpPaymentKey(addr *cardano.Address) {
	if addr.Payment.Type != cardano.KeyCredential {
		fmt.Println("invalid payment type")
	} else {
		fmt.Printf("Payment key hash: %v\n", addr.Payment.KeyHash.String())
	}
}

func dumpPaymentScript(addr *cardano.Address) {
	if addr.Payment.Type != cardano.ScriptCredential {
		fmt.Println("invalid payment type")
	} else {
		fmt.Printf("Payment script hash: %v\n", addr.Payment.ScriptHash.String())
	}
}

func dumpStakeKey(addr *cardano.Address) {
	if addr.Stake.Type != cardano.KeyCredential {
		fmt.Println("invalid stake type")
	} else {
		fmt.Printf("Stake key hash: %v\n", addr.Stake.KeyHash.String())
	}
}

func dumpStakeScript(addr *cardano.Address) {
	if addr.Stake.Type != cardano.ScriptCredential {
		fmt.Println("invalid stake type")
	} else {
		fmt.Printf("Stake script hash: %v\n", addr.Stake.ScriptHash.String())
	}
}
