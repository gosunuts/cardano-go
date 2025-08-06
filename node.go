package cardano

import "context"

const (
	ProtocolMagic = 1097911063
)

// Node is the interface required for a Cardano backend/node.
// A backend/node is used to interact with the Cardano Blockchain,
// sending transactions and fetching state.
type Node interface {
	// UTxOs returns a list of unspent transaction outputs for a given address
	UTxOs(context.Context, Address) ([]UTxO, error)

	// Tip returns the node's current tip
	Tip(context.Context) (*NodeTip, error)

	// SubmitTx submits a transaction to the node using cbor encoding
	SubmitTx(context.Context, *Tx) (*Hash32, error)

	// ProtocolParams returns the Node's Protocol Parameters
	ProtocolParams(context.Context) (*ProtocolParams, error)

	// Network returns the node's current network type
	Network() Network
}

type NodeTip struct {
	Block uint64
	Epoch uint64
	Slot  uint64
}
