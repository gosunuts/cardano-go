package blockfrost

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/blockfrost/blockfrost-go"
	"github.com/gosunuts/cardano-go"
)

// BlockfrostNode implements Node using the blockfrost API.
type BlockfrostNode struct {
	client    blockfrost.APIClient
	projectID string
	network   cardano.Network
	server    string
}

// check interface
var _ cardano.Node = (*BlockfrostNode)(nil)

func NewCustomNode(network cardano.Network, projectID, server string) *BlockfrostNode {
	return &BlockfrostNode{
		network:   network,
		projectID: projectID,
		server:    server,
		client: blockfrost.NewAPIClient(blockfrost.APIClientOptions{
			ProjectID: projectID,
			Server:    server,
		}),
	}

}

// NewNode returns a new instance of BlockfrostNode.
func NewNode(network cardano.Network, projectID string) *BlockfrostNode {
	server := blockfrost.CardanoMainNet
	switch network {
	case cardano.Preview:
		server = blockfrost.CardanoPreview
	case cardano.Preprod:
		server = blockfrost.CardanoPreProd
	}

	return &BlockfrostNode{
		network:   network,
		projectID: projectID,
		server:    server,
		client: blockfrost.NewAPIClient(blockfrost.APIClientOptions{
			ProjectID: projectID,
			Server:    server,
		}),
	}
}

func (b *BlockfrostNode) UTxOs(ctx context.Context, addr cardano.Address) ([]cardano.UTxO, error) {
	butxos, err := b.addressUTXOsAll(ctx, addr.Bech32(), blockfrost.APIQueryParams{})
	if err != nil {
		// Addresses without UTXOs return NotFound error
		if err, ok := err.(*blockfrost.APIError); ok {
			if _, ok := err.Response.(blockfrost.NotFound); ok {
				return []cardano.UTxO{}, nil
			}
		}
		return nil, err
	}

	utxos := make([]cardano.UTxO, len(butxos))

	for i, butxo := range butxos {
		txHash, err := cardano.NewHash32(butxo.TxHash)
		if err != nil {
			return nil, err
		}

		amount := cardano.NewValue(0)
		for _, a := range butxo.Amount {
			if a.Unit == "lovelace" {
				lovelace, err := strconv.ParseUint(a.Quantity, 10, 64)
				if err != nil {
					return nil, err
				}
				amount.Coin += cardano.Coin(lovelace)
			} else {
				unitBytes, err := hex.DecodeString(a.Unit)
				if err != nil {
					return nil, err
				}
				policyID := cardano.NewPolicyIDFromHash(unitBytes[:28])
				assetName := string(unitBytes[28:])
				assetValue, err := strconv.ParseUint(a.Quantity, 10, 64)
				if err != nil {
					return nil, err
				}
				currentAssets := amount.MultiAsset.Get(policyID)
				if currentAssets != nil {
					currentAssets.Set(
						cardano.NewAssetName(assetName),
						cardano.BigNum(assetValue),
					)
				} else {
					amount.MultiAsset.Set(
						policyID,
						cardano.NewAssets().
							Set(
								cardano.NewAssetName(assetName),
								cardano.BigNum(assetValue),
							),
					)
				}
			}
		}

		utxos[i] = cardano.UTxO{
			Spender: addr,
			TxHash:  txHash,
			Amount:  amount,
			Index:   uint64(butxo.OutputIndex),
		}
	}

	return utxos, nil
}

func (b *BlockfrostNode) addressUTXOsAll(ctx context.Context, address string, queryParams blockfrost.APIQueryParams) ([]blockfrost.AddressUTXO, error) {
	result := make([]blockfrost.AddressUTXO, 0, 100)

	for page := 0; ; page++ {
		query := queryParams
		query.Count = 100
		query.Page = page
		utxo, err := b.client.AddressUTXOs(ctx, address, query)
		switch {
		case err != nil:
			return nil, err
		case len(utxo) == 0:
			return result, nil
		}
		result = append(result, utxo...)
		if len(utxo) != query.Count {
			return result, nil
		}
	}
}

func (b *BlockfrostNode) Tip(ctx context.Context) (*cardano.NodeTip, error) {
	block, err := b.client.BlockLatest(ctx)
	if err != nil {
		return nil, err
	}

	return &cardano.NodeTip{
		Block: uint64(block.Height),
		Epoch: uint64(block.Epoch),
		Slot:  uint64(block.Slot),
	}, nil
}

func (b *BlockfrostNode) SubmitTx(ctx context.Context, tx *cardano.Tx) (*cardano.Hash32, error) {
	url := b.server + "/tx/submit"
	txBytes := tx.Bytes()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(txBytes))
	if err != nil {
		return nil, err
	}

	req.Header.Add("project_id", b.projectID)
	req.Header.Add("Content-Type", "application/cbor")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(string(respBody))
	}

	txHash, err := tx.Hash()
	if err != nil {
		return nil, err
	}

	return &txHash, nil
}

func (b *BlockfrostNode) ProtocolParams(ctx context.Context) (*cardano.ProtocolParams, error) {
	eparams, err := b.client.LatestEpochParameters(ctx)
	if err != nil {
		return nil, err
	}

	minUTXO, err := strconv.ParseUint(eparams.MinUtxo, 10, 64)
	if err != nil {
		return nil, err
	}

	poolDeposit, err := strconv.ParseUint(eparams.PoolDeposit, 10, 64)
	if err != nil {
		return nil, err
	}
	keyDeposit, err := strconv.ParseUint(eparams.KeyDeposit, 10, 64)
	if err != nil {
		return nil, err
	}

	pparams := &cardano.ProtocolParams{
		MinFeeA:            cardano.Coin(eparams.MinFeeA),
		MinFeeB:            cardano.Coin(eparams.MinFeeB),
		MaxBlockBodySize:   uint(eparams.MaxBlockSize),
		MaxTxSize:          uint(eparams.MaxTxSize),
		MaxBlockHeaderSize: uint(eparams.MaxBlockHeaderSize),
		KeyDeposit:         cardano.Coin(keyDeposit),
		PoolDeposit:        cardano.Coin(poolDeposit),
		MaxEpoch:           uint(eparams.Epoch),
		NOpt:               uint(eparams.NOpt),
		CoinsPerUTXOWord:   cardano.Coin(minUTXO),
	}

	return pparams, nil
}

func (b *BlockfrostNode) Network() cardano.Network {
	return b.network
}
