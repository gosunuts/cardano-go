package main

import (
	"context"

	"github.com/gosunuts/cardano-go/cmd/cardano-tool/handler"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "cardano-tool",
		Short: "A CLI application to operate keys in Cardano.",
	}

	ctx := context.Background()
	keyCmd := handler.NewKeyCmdHandler()
	txCmd := handler.NewTxCmdHandler()
	rootCmd.AddCommand(keyCmd.Commands(ctx)...)
	rootCmd.AddCommand(txCmd.Commands(ctx)...)

	cobra.CheckErr(rootCmd.ExecuteContext(ctx))
}
