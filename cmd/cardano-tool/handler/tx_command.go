package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cryptogarageinc/cardano-go"
	"github.com/cryptogarageinc/cardano-go/crypto"
	"github.com/spf13/cobra"
)

type txCmdHandler struct {
}

func NewTxCmdHandler() *txCmdHandler {
	return &txCmdHandler{}
}

func (h *txCmdHandler) Commands(ctx context.Context) []*cobra.Command {
	return []*cobra.Command{
		h.buildTxCmd(ctx),
		h.dumpTxCmd(ctx),
	}
}

func (h *txCmdHandler) buildTxCmd(_ context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "buildTx",
		Short: "build transaction",
		Long:  `Build a transaction.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			inputs, _ := cmd.Flags().GetString("inputs")
			if inputs == "" {
				return errors.New("invalid request. inputs is empty")
			}
			outputs, _ := cmd.Flags().GetString("outputs")
			if outputs == "" {
				return errors.New("invalid request. outputs is empty")
			}
			minFeeAStr, _ := cmd.Flags().GetString("minFeeA")
			if minFeeAStr == "" {
				return errors.New("invalid request. minFeeA is empty")
			}
			minFeeA, err := strconv.ParseUint(minFeeAStr, 10, 64)
			if err != nil {
				return err
			}
			minFeeBStr, _ := cmd.Flags().GetString("minFeeB")
			if minFeeBStr == "" {
				return errors.New("invalid request. minFeeB is empty")
			}
			minFeeB, err := strconv.ParseUint(minFeeBStr, 10, 64)
			if err != nil {
				return err
			}
			coinsPerUTXOWordStr, _ := cmd.Flags().GetString("coinsPerUTXOWord")
			if coinsPerUTXOWordStr == "" {
				return errors.New("invalid request. coinsPerUTXOWord is empty")
			}
			coinsPerUTXOWord, err := strconv.ParseUint(coinsPerUTXOWordStr, 10, 64)
			if err != nil {
				return err
			}
			changeAddress, _ := cmd.Flags().GetString("changeAddress")
			keysStr, _ := cmd.Flags().GetString("keys")

			tx, err := buildTx(inputs, outputs, minFeeA, minFeeB, coinsPerUTXOWord, changeAddress, keysStr)
			if err != nil {
				return err
			}
			hash, err := tx.Hash()
			if err != nil {
				return err
			}
			fmt.Printf("tx  : %v\n", tx.Hex())
			fmt.Printf("hash: %v\n", hash.String())
			return nil
		},
	}

	cmd.Flags().StringP("inputs", "i", "", `input list by json. ex: '[{"txHash":"7b240d1907090478f08e5b2cac2c5e0da5a76a511390fa5aa962d540fba8f8d4","index":0,"amount":{"coin":"10000000000"}},...]'`)
	cmd.Flags().StringP("outputs", "o", "", `output list by json. ex: '[{"address":"addr_test1vqeux7xwusdju9dvsj8h7mca9aup2k439kfmwy773xxc2hcu7zy99","amount":{"coin":"9000000000"}},...]'`)
	cmd.Flags().StringP("minFeeA", "a", "", "MinFeeA")
	cmd.Flags().StringP("minFeeB", "b", "", "MinFeeB")
	cmd.Flags().StringP("coinsPerUTXOWord", "u", "", "CoinsPerUTXOWord")
	cmd.Flags().StringP("changeAddress", "c", "", "change address if needed")
	cmd.Flags().StringP("keys", "k", "", "key list order by tx inputs")
	return cmd
}

func buildTx(
	inputs, outputs string,
	minFeeA, minFeeB, coinsPerUTXOWord uint64,
	changeAddress, keysStr string,
) (*cardano.Tx, error) {
	txInputs := []*cardano.TxInput{}
	txOutputs := make([]*cardano.TxOutput, 0)

	if err := json.Unmarshal([]byte(inputs), &txInputs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(outputs), &txOutputs); err != nil {
		return nil, err
	}
	for i, txInput := range txInputs {
		if txInput.Amount.MultiAsset == nil {
			txInput.Amount.MultiAsset = cardano.NewMultiAsset()
			txInputs[i] = txInput
		}
	}
	for i, txOutput := range txOutputs {
		if txOutput.Amount.MultiAsset == nil {
			txOutput.Amount.MultiAsset = cardano.NewMultiAsset()
			txOutputs[i] = txOutput
		}
	}

	builder := cardano.NewTxBuilder(&cardano.ProtocolParams{
		MinFeeA:          cardano.Coin(minFeeA),
		MinFeeB:          cardano.Coin(minFeeB),
		CoinsPerUTXOWord: cardano.Coin(coinsPerUTXOWord),
	})
	builder.AddInputs(txInputs...)
	builder.AddOutputs(txOutputs...)
	if changeAddress != "" {
		changeAddr, err := cardano.NewAddress(changeAddress)
		if err != nil {
			return nil, err
		}
		builder.AddChangeIfNeeded(changeAddr)
	}

	keys := make([]crypto.PrvKey, 0, len(txInputs))
	keyStrList := strings.Split(keysStr, ",")
	for _, keyStr := range keyStrList {
		if _, isXpriv := crypto.GetKeyPrefixByXpriv(keyStr); isXpriv {
			xpriv, err := crypto.NewXPrvKey(keyStr)
			if err != nil {
				return nil, err
			}
			keys = append(keys, xpriv.PrvKey())
		} else {
			sk, err := crypto.NewPrvKey(keyStr)
			if err == nil {
				keys = append(keys, sk)
			} else {
				skBytes, tmpErr := hex.DecodeString(keyStr)
				if tmpErr != nil {
					return nil, err
				}
				if len(skBytes)*2 != len(keyStr) {
					return nil, err
				}
				keys = append(keys, crypto.PrvKey(skBytes))
			}
		}
	}
	if len(keyStrList) == 0 {
		// Set a dummy private key to calculate the fee.
		xprv, err := crypto.NewXPrvKey(dummyRootXsk)
		if err != nil {
			return nil, err
		}
		for i := range txInputs {
			childKey := xprv.Derive(uint32(i))
			keys = append(keys, childKey.PrvKey())
		}
	}
	builder.Sign(keys...)

	return builder.Build()
}

func (h *txCmdHandler) dumpTxCmd(_ context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dumpTx",
		Short: "dump transaction",
		Long:  `Dump a transaction.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			txStr, _ := cmd.Flags().GetString("tx")
			if txStr == "" {
				err := errors.New("invalid request. tx is empty")
				return err
			}

			txBytes, err := hex.DecodeString(txStr)
			if err != nil {
				return err
			}
			tx := cardano.Tx{}
			if err := tx.UnmarshalCBOR(txBytes); err != nil {
				return err
			}
			txHash, err := tx.Hash()
			if err != nil {
				return err
			}

			fmt.Printf("hash: %v\n", txHash.String())
			fmt.Printf("IsValid: %v\n", tx.IsValid)
			fmt.Println("txInputs:")
			for i, txInput := range tx.Body.Inputs {
				fmt.Printf("- [%d]: %v:%v\n", i, txInput.TxHash.String(), txInput.Index)
			}
			fmt.Println("txOutputs:")
			for i, txOutput := range tx.Body.Outputs {
				fmt.Printf("- [%d]: %s\n", i, txOutput.Address.Bech32())
				if txOutput.Amount == nil {
					fmt.Println("  coin: nil")
				} else {
					fmt.Printf("  coin: %d\n", txOutput.Amount.Coin)
					fmt.Printf("  assets: %s\n", txOutput.Amount.MultiAsset.String())
				}
			}
			fmt.Printf("WitnessSet: %v\n", tx.WitnessSet)
			fmt.Printf("AuxiliaryData: %v\n", tx.AuxiliaryData)
			return nil
		},
	}

	cmd.Flags().StringP("tx", "t", "", "transaction hex")
	return cmd
}

var dummyRootXsk = "root_xsk1cpj6l55r9nvtpp7ymx4hqy05s8hpupepu782thtqnuat8u2k6fzaza4a3l2wcc95wvwrjx9z5u4qyfkqe5geas6mgljd2kyyvel4223r7l7u6jsscmxjcuun43sasau88cjg7stkxj4rmqf27vnll6wkyqya0lre"
