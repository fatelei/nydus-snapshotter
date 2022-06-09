package main

import (
	"context"
	"github.com/containerd/nydus-snapshotter/config"
	"os"
	"os/signal"
	"syscall"

	"github.com/containerd/containerd/log"
	"github.com/containerd/nydus-snapshotter/pkg/additionlayerstore/fs"
)

func main() {
	ctx := context.Background()
	mountPoint := "/var/lib/nydus-store/store"
	var cfg config.Config
	if err := fs.Mount(ctx, mountPoint, true, &cfg); err != nil {
		log.G(ctx).WithError(err).Fatalf("failed to mount fs at %q", mountPoint)
	}
	defer func() {
		syscall.Unmount(mountPoint, 0)
		log.G(ctx).Info("Exiting")
	}()
	waitForSIGINT()
}

func waitForSIGINT() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}