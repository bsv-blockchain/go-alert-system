// Package main is the entry point for the alert-system
package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/bsv-blockchain/go-alert-system/app/config"
	"github.com/bsv-blockchain/go-alert-system/app/models"
	"github.com/bsv-blockchain/go-alert-system/app/models/model"
	"github.com/bsv-blockchain/go-alert-system/app/p2p"
	"github.com/bsv-blockchain/go-alert-system/app/webserver"
)

// main is the entry point for the alert-system
func main() {
	// Load the configuration and services
	_appConfig, err := config.LoadDependencies(context.Background(), models.BaseModels, false)
	if err != nil {
		log.Fatalf("error loading configuration: %s", err.Error())
	}
	defer func() {
		_appConfig.CloseAll(context.Background())
	}()

	// Check the RPC connection (unless disabled) and refuse development genesis keys outside regtest
	// before they are stored. The chain is always checked when development keys are configured,
	// even with RPC verification disabled, since nothing else stops them being trusted.
	ctx := context.Background()
	trustRoot := &trustRootCheck{node: _appConfig.Services.Node}
	if err = trustRoot.verify(ctx, _appConfig.GenesisKeys, !_appConfig.DisableRPCVerification); err != nil {
		_appConfig.Services.Log.Fatalf("refusing to start: %s", err.Error())
	}

	// Ensure we have the genesis alert in the database
	if err = models.CreateGenesisAlert(ctx, model.WithAllDependencies(_appConfig)); err != nil {
		_appConfig.Services.Log.Fatalf("error creating genesis alert: %s", err.Error())
	}

	// The active keys in the datastore are the trust root, and a persisted datastore can hold
	// keys from an earlier configuration, so check them too
	var activeKeys []*models.PublicKey
	if activeKeys, err = models.GetActivePublicKey(ctx, nil, model.WithAllDependencies(_appConfig)); err != nil {
		_appConfig.Services.Log.Fatalf("error getting the active public keys: %s", err.Error())
	}
	keys := make([]string, 0, len(activeKeys))
	for _, key := range activeKeys {
		keys = append(keys, key.Key)
	}
	if err = trustRoot.verify(ctx, keys, false); err != nil {
		_appConfig.Services.Log.Fatalf("refusing to start: active key set in the datastore: %s", err.Error())
	}

	// Create the p2p server
	var p2pServer *p2p.Server
	if p2pServer, err = p2p.NewServer(p2p.ServerOptions{
		TopicNames: []string{_appConfig.P2P.TopicName},
		Config:     _appConfig,
	}); err != nil {
		_appConfig.Services.Log.Fatalf("error creating p2p server: %s", err.Error())
	}

	// Create a new (web) server
	webServer := webserver.NewServer(_appConfig, p2pServer)

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	// Start the p2p server
	if err = p2pServer.Start(ctx); err != nil {
		_appConfig.Services.Log.Fatalf("error starting p2p server: %s", err.Error())
	}
	// Sync a channel to listen for interrupts
	idleConnectionsClosed := make(chan struct{})
	go func(appConfig *config.Config) {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)

		// Log when a signal is received
		appConfig.Services.Log.Debugf("waiting for interrupt signal")
		<-sigint

		// Log that we are starting the shutdown process
		appConfig.Services.Log.Infof("interrupt signal received, starting shutdown process")

		// We received an interrupt signal, shut down the server
		ctxTimeout, cancel := context.WithTimeout(context.Background(), config.DefaultServerShutdown)
		defer cancel()
		if err = webServer.Shutdown(ctxTimeout); err != nil {
			appConfig.Services.Log.Infof("error shutting down webserver: %s", err.Error())
		}

		// Shutdown the p2p server
		if err = p2pServer.Stop(ctxTimeout); err != nil {
			appConfig.Services.Log.Infof("error shutting down p2p server: %s", err.Error())
		}
		cancelFunc()
		appConfig.Services.Log.Infof("successfully shut down server")
		close(idleConnectionsClosed)
		if err = appConfig.Services.Log.CloseWriter(); err != nil {
			log.Printf("error closing logger: %s", err)
		}
	}(_appConfig)

	// Serve the web server and then wait endlessly
	webServer.Serve()

	// Wait for the idle connection to close
	<-idleConnectionsClosed
}
