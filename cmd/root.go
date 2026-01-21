package cmd

import (
	"fmt"
	"os"

	"github.com/SafeMPC/mpc-signer/cmd/cert"
	"github.com/SafeMPC/mpc-signer/cmd/db"
	"github.com/SafeMPC/mpc-signer/cmd/env"
	"github.com/SafeMPC/mpc-signer/cmd/probe"
	"github.com/SafeMPC/mpc-signer/cmd/server"
	"github.com/SafeMPC/mpc-signer/internal/config"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Version: config.GetFormattedBuildArgs(),
	Use:     "app",
	Short:   config.ModuleName,
	Long: fmt.Sprintf(`%v

A stateless RESTful JSON service written in Go.
Requires configuration through ENV.`, config.ModuleName),
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.SetVersionTemplate(`{{printf "%s\n" .Version}}`)

	// attach the subcommands
	rootCmd.AddCommand(
		cert.New(),
		db.New(),
		env.New(),
		probe.New(),
		server.New(),
	)

	if err := rootCmd.Execute(); err != nil {
		log.Error().Err(err).Msg("Failed to execute root command")
		os.Exit(1)
	}
}
