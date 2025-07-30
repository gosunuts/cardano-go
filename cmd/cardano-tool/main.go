package main

import (
	"context"

	"github.com/cryptogarageinc/cardano-go/cmd/cardano-tool/handler"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "cardano-tool",
		Short: "A CLI application to operate keys in Cardano.",
	}

	ctx := context.Background()
	keyCmd := handler.NewKeyCmdHandler()
	rootCmd.AddCommand(keyCmd.Commands(ctx)...)

	cobra.CheckErr(rootCmd.ExecuteContext(ctx))
}
