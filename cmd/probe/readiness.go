package probe

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/SafeMPC/mpc-signer/internal/api"
	"github.com/SafeMPC/mpc-signer/internal/config"
	"github.com/SafeMPC/mpc-signer/internal/util"
	"github.com/SafeMPC/mpc-signer/internal/util/command"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type ReadinessFlags struct {
	Verbose bool
}

func newReadiness() *cobra.Command {
	var flags ReadinessFlags

	cmd := &cobra.Command{
		Use:   "readiness",
		Short: "Runs readiness probes",
		Long: `Runs connection readinesss probes
	
	This command triggers the same readinesss probes as in
	/-/ready (apart from the actual server.ready 
	probe) and prints the results to stdout. Fails with
	non zero exitcode on encountered errors.
	
	A typical usecase of this command are readiness probes 
	to take action if dependant services (e.g. DB, NFS 
	mounts) become unstable. You may also use this to 
	ensure all requirements are fulfilled before starting
	the app server.`,
		Run: func(_ *cobra.Command, _ []string /* args */) {
			readinessCmdFunc(flags)
		},
	}

	cmd.Flags().BoolVarP(&flags.Verbose, verboseFlag, "v", false, "Show verbose output.")

	return cmd
}

func readinessCmdFunc(flags ReadinessFlags) {
	err := command.WithServer(context.Background(), config.DefaultServiceConfigFromEnv(), func(ctx context.Context, s *api.Server) error {
		log := util.LogFromContext(ctx)

		errs, err := RunReadiness(ctx, s.Config, flags)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to run readiness probes")
		}

		if len(errs) > 0 {
			log.Fatal().Errs("errs", errs).Msg("Unhealthy.")
		}

		return nil
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to run readiness probes")
	}
}

func RunReadiness(ctx context.Context, config config.Server, flags ReadinessFlags) ([]error, error) {
	log := util.LogFromContext(ctx)

	db, err := sql.Open("postgres", config.Database.ConnectionString())
	if err != nil {
		log.Error().Err(err).Msg("Failed to open the database")
		return nil, fmt.Errorf("failed to open the database: %w", err)
	}
	defer db.Close()

	readinessCtx, cancel := context.WithTimeout(context.Background(), config.Management.ReadinessTimeout)
	defer cancel()

	// ProbeReadiness 功能已简化（signer 节点不需要复杂的健康检查）
	var errs []error
	str := "Readiness check passed"
	if err := db.PingContext(readinessCtx); err != nil {
		errs = append(errs, fmt.Errorf("database ping failed: %w", err))
		str = "Readiness check failed"
	}

	if flags.Verbose {
		log.Info().Msg(str)
	}

	return errs, nil
}
