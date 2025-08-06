package blockfrost

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/cryptogarageinc/cardano-go"
)

func TestUTxOs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}
	projectID := os.Getenv("BLOCKFROST_PROJECT_ID")
	if projectID == "" {
		t.Fatal("env:BLOCKFROST_PROJECT_ID is not set")
	}
	cli := NewNode(cardano.Mainnet, projectID)
	addr, err := cardano.NewAddress("addr1qyfrk9v8pav67pqx9s7wt6l37ml8za4yw8p3xd7zn8kt8v33mh63ch0lef8trccuw49l6nrqhqcdmwrnj9hwzch8ahksfy40jm")
	if err != nil {
		t.Fatal(err)
	}
	utxos, err := cli.UTxOs(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("utxo: %v\n", utxos)
}

func TestTip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}
	projectID := os.Getenv("BLOCKFROST_PROJECT_ID")
	if projectID == "" {
		t.Fatal("env:BLOCKFROST_PROJECT_ID is not set")
	}
	cli := NewNode(cardano.Mainnet, projectID)
	nodeTip, err := cli.Tip(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("nodeTip: %v\n", nodeTip)
}

func TestProtocolParams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}
	projectID := os.Getenv("BLOCKFROST_PROJECT_ID")
	if projectID == "" {
		t.Fatal("env:BLOCKFROST_PROJECT_ID is not set")
	}
	cli := NewNode(cardano.Mainnet, projectID)
	protocolParams, err := cli.ProtocolParams(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("protocolParams: %v\n", protocolParams)
}
