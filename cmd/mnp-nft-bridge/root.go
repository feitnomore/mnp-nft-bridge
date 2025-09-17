/**
 * Copyright 2025 Marcelo Parisi (github.com/feitnomore)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/feitnomore/mnp-nft-bridge/pkg/controller"
	"github.com/feitnomore/mnp-nft-bridge/pkg/kernel"
	"github.com/feitnomore/mnp-nft-bridge/pkg/node"
	"github.com/feitnomore/mnp-nft-bridge/pkg/types"
	"github.com/feitnomore/mnp-nft-bridge/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

/* Our version */
var version = "dev"

/* Our nftables utility */
var thisNft = types.NewNftTables()

/* Cobra Root Command */
var rootCmd = &cobra.Command{
	Use:     "mnp-nft-bridge",
	Version: version,
	Short:   "MultinetworkPolicy Bridge Controller",
	Long:    "mnp-nft-bridge - Kubernetes MultinetworkPolicy Bridge Controller.",
	Run: func(_ *cobra.Command, args []string) {
		/* Make sure klog use the values got by Crobra/pflag */
		klog.OsExit = func(exitCode int) {
			klog.Errorf("klog.OsExit called with code %d, panicking to allow flush", exitCode)
			panic(fmt.Sprintf("klog.OsExit called with code %d", exitCode))
		}
		/* Force log to stderr */
		klog.LogToStderr(true)

		stopCh := make(chan struct{})
		defer close(stopCh)

		klog.V(8).Infof("creating controllers: controller.NewControllers() \n")
		ctrl, err := controller.NewControllers(thisNft)
		if err != nil {
			klog.Errorf("controller.NewControllers() falied: %v \n", err)
			os.Exit(1)
		}

		klog.V(8).Infof("starting controllers: controller.Run() \n")
		if err := ctrl.Run(stopCh); err != nil {
			klog.Errorf("ctrl.Run() failed: %v \n", err)
			os.Exit(1)
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		klog.Infof("Waiting for shutdown signal...")
		<-sigChan
		klog.Infof("Shutdown signal received, exiting...\n")

		_ = args
	},
}

//nolint:gochecknoinits
func init() {
	defer klog.Flush()

	/* Create pflag.FlagSet for klog flags */
	klogFlags := pflag.NewFlagSet("klog", pflag.ContinueOnError)

	/* Initialize klog flags using a temporary *flag.FlagSet */
	goFlags := flag.NewFlagSet("go-flags-for-klog", flag.ContinueOnError)
	klog.InitFlags(goFlags)

	/* Add values from *flag.FlagSet to Cobra's *pflag.FlagSet */
	goFlags.VisitAll(func(f *flag.Flag) {
		pf := pflag.PFlagFromGoFlag(f)
		klogFlags.AddFlag(pf)
	})

	/* Add flags to our rootCmd */
	rootCmd.PersistentFlags().AddFlagSet(klogFlags)

	if lf := rootCmd.PersistentFlags().Lookup("logtostderr"); lf != nil {
		lf.DefValue = "true"
		lf.NoOptDefVal = "true"

		if err := rootCmd.PersistentFlags().Set("logtostderr", "true"); err != nil {
			klog.Warningf("Failed to set logtostderr via pflag in init: %v", err)
		}
	} else {
		klog.Warning("klog flag 'logtostderr' not found in PersistentFlags during init.")
	}
}

/* This is our controller starting point */
func main() {
	utils.DisplayBanner(version)

	if !kernel.CheckNftables() {
		klog.Errorf("Error matching nftables kernel modules...\n")
		klog.Flush()
		os.Exit(1)
	}

	host := node.GetNodeHostname()
	if host == "" {
		klog.Errorf("Hosname returned empty string...\n")
		klog.Flush()
		os.Exit(1)
	}

	thisNft.Init()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing root command: %v\n", err)
		klog.Fatalf("Error executing root command: %v \n", err)
	}
}
