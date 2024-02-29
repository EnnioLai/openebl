package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	formatter "github.com/bluexlab/logrus-formatter"
	"github.com/gobuffalo/pop"
	"github.com/gobuffalo/pop/logging"
	"github.com/openebl/openebl/pkg/bu_server/api"
	"github.com/openebl/openebl/pkg/bu_server/manager"
	"github.com/openebl/openebl/pkg/config"
	"github.com/openebl/openebl/pkg/util"
	"github.com/sirupsen/logrus"
)

type CLI struct {
	Server struct {
	} `cmd:"" help:"Run the server"`
	Migrate struct {
		Path string `short:"p" long:"path" help:"Path to the migration files" default:"migrations"`
	} `cmd:"" help:"Migrate the database"`
	Config string `short:"c" long:"config" help:"Path to the configuration file" default:"config.yaml"`
}

type Config struct {
	Database util.PostgresDatabaseConfig `yaml:"database"`
	Server   struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"server"`
	Manager struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"manager"`
}

type App struct{}

func (a *App) Run() {
	formatter.InitLogger()

	var cli CLI
	ctx := kong.Parse(&cli, kong.UsageOnError())
	switch ctx.Command() {
	case "server":
		a.runServer(cli)
	case "migrate":
		a.runMigrate(cli)
	default:
	}
}

func (a *App) runServer(cli CLI) {
	var appConfig Config
	if err := config.FromFile(cli.Config, &appConfig); err != nil {
		logrus.Errorf("failed to load config: %v", err)
		os.Exit(128)
	}

	apiConfig := api.APIConfig{
		Database:     appConfig.Database,
		LocalAddress: net.JoinHostPort(appConfig.Server.Host, strconv.Itoa(appConfig.Server.Port)),
	}
	apiServer, err := api.NewAPIWithConfig(apiConfig)
	if err != nil {
		logrus.Errorf("failed to create API server: %v", err)
		os.Exit(128)
	}

	managerAPIConfig := manager.ManagerAPIConfig{
		Database:     appConfig.Database,
		LocalAddress: net.JoinHostPort(appConfig.Manager.Host, strconv.Itoa(appConfig.Manager.Port)),
	}
	managerServer, err := manager.NewManagerAPI(managerAPIConfig)
	if err != nil {
		logrus.Errorf("failed to create Manager server: %v", err)
		os.Exit(128)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	wg := &sync.WaitGroup{}

	go func(wg *sync.WaitGroup) {
		wg.Add(1)
		defer wg.Done()
		if err := apiServer.Run(); err != nil {
			logrus.Errorf("failed to run API server: %v", err)
			os.Exit(1)
		}
	}(wg)

	go func(wg *sync.WaitGroup) {
		wg.Add(1)
		defer wg.Done()
		if err := managerServer.Run(); err != nil {
			logrus.Errorf("failed to run Manager server: %v", err)
			os.Exit(1)
		}
	}(wg)

	// listen for the stop signal
	<-ctx.Done()

	// Restore default behavior on the signals we are listening to
	stop()
	logrus.Info("shutting down gracefully, press Ctrl+C again to force")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := apiServer.Close(ctx); err != nil {
		logrus.Warnf("failed to close API server: %v", err)
		os.Exit(1)
	}
	if err := managerServer.Close(ctx); err != nil {
		logrus.Warnf("failed to close Manager server: %v", err)
		os.Exit(1)
	}

	wg.Wait()
}

func (a *App) runMigrate(cli CLI) {
	var cfg Config
	if err := config.FromFile(cli.Config, &cfg); err != nil {
		logrus.Errorf("failed to load config: %v", err)
		os.Exit(128)
	}

	// set up the logger
	pop.SetLogger(func(lvl logging.Level, s string, args ...interface{}) {
		switch lvl {
		case logging.Debug:
			logrus.Debugf(s, args...)
		case logging.Info:
			logrus.Infof(s, args...)
		case logging.Warn:
			logrus.Warnf(s, args...)
		case logging.Error:
			logrus.Errorf(s, args...)
		case logging.SQL:
			// Do nothing
		}
	})

	// setup database connection
	cd := pop.ConnectionDetails{
		Dialect:  "postgres",
		Database: cfg.Database.Database,
		Host:     cfg.Database.Host,
		Port:     strconv.Itoa(cfg.Database.Port),
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
	}
	conn, err := pop.NewConnection(&cd)
	if err != nil {
		logrus.Errorf("failed to create connection: %v", err)
		os.Exit(128)
	}

	// create the database if it doesn't exist
	if err = conn.Dialect.CreateDB(); err != nil {
		logrus.Warnf("failed to create database: %v", err)
	}

	migrator, err := pop.NewFileMigrator(cli.Migrate.Path, conn)
	if err != nil {
		logrus.Errorf("failed to create migrator: %v", err)
		os.Exit(128)
	}
	// Remove SchemaPath to prevent migrator try to dump schema.
	migrator.SchemaPath = ""

	// run the migrations
	if err = migrator.Up(); err != nil {
		logrus.Errorf("failed to migrate: %v", err)
		os.Exit(1)
	}
}
