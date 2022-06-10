/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"os"
	"strings"

	"github.com/containerd/nydus-snapshotter/config"
	"github.com/containerd/nydus-snapshotter/pkg/cache"
	"github.com/containerd/nydus-snapshotter/pkg/filesystem/fs"
	"github.com/containerd/nydus-snapshotter/pkg/filesystem/meta"
	"github.com/containerd/nydus-snapshotter/pkg/process"
	"github.com/containerd/nydus-snapshotter/pkg/signature"
	"github.com/pkg/errors"
)

type NewFSOpt func(d *NydusFilesystem) error

func WithMeta(root string) NewFSOpt {
	return func(d *NydusFilesystem) error {
		if root == "" {
			return errors.New("rootDir is required")
		}
		d.FileSystemMeta = meta.FileSystemMeta{
			RootDir: root,
		}
		return nil
	}
}

func WithNydusdBinaryPath(p string, daemonMode string) NewFSOpt {
	return func(d *NydusFilesystem) error {
		if daemonMode != config.DaemonModeNone && p == "" {
			return errors.New("nydusd binary path is required")
		}
		d.nydusdBinaryPath = p
		return nil
	}
}

func WithProcessManager(pm *process.Manager) NewFSOpt {
	return func(d *NydusFilesystem) error {
		if pm == nil {
			return errors.New("process manager cannot be nil")
		}

		d.manager = pm
		return nil
	}
}

func WithCacheManager(cm *cache.Manager) NewFSOpt {
	return func(d *NydusFilesystem) error {
		if cm == nil {
			return errors.New("cache manager cannot be nil")
		}

		d.cacheMgr = cm
		return nil
	}
}

func WithVerifier(verifier *signature.Verifier) NewFSOpt {
	return func(d *NydusFilesystem) error {
		d.verifier = verifier
		return nil
	}
}

func WithDaemonConfig(cfg config.DaemonConfig) NewFSOpt {
	return func(d *NydusFilesystem) error {
		if (config.DaemonConfig{}) == cfg {
			return errors.New("daemon config is empty")
		}
		d.daemonCfg = cfg
		return nil
	}
}

func WithVPCRegistry(vpcRegistry bool) NewFSOpt {
	return func(d *NydusFilesystem) error {
		d.vpcRegistry = vpcRegistry
		return nil
	}
}

func WithDaemonMode(daemonMode string) NewFSOpt {
	return func(d *NydusFilesystem) error {
		mode := strings.ToLower(daemonMode)
		switch mode {
		case config.DaemonModeNone:
			d.mode = fs.NoneInstance
		case config.DaemonModeShared:
			d.mode = fs.SharedInstance
		case config.DaemonModePrefetch:
			d.mode = fs.PrefetchInstance
		case config.DaemonModeMultiple:
			fallthrough
		default:
			d.mode = fs.MultiInstance
		}
		return nil
	}
}

func WithDaemonBackend(daemonBackend string) NewFSOpt {
	return func(d *NydusFilesystem) error {
		switch daemonBackend {
		case config.DaemonBackendFscache:
			d.daemonBackend = config.DaemonBackendFscache
		default:
			d.daemonBackend = config.DaemonBackendFusedev
		}
		return nil
	}
}

func WithLogLevel(logLevel string) NewFSOpt {
	return func(d *NydusFilesystem) error {
		if logLevel == "" {
			d.logLevel = config.DefaultLogLevel
		} else {
			d.logLevel = logLevel
		}
		return nil
	}
}

func WithLogDir(dir string) NewFSOpt {
	return func(d *NydusFilesystem) error {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return errors.Errorf("failed to create logDir %s: %v", dir, err)
		}
		d.logDir = dir
		return nil
	}
}

func WithLogToStdout(logToStdout bool) NewFSOpt {
	return func(d *NydusFilesystem) error {
		d.logToStdout = logToStdout
		return nil
	}
}

func WithNydusdThreadNum(nydusdThreadNum int) NewFSOpt {
	return func(d *NydusFilesystem) error {
		d.nydusdThreadNum = nydusdThreadNum
		return nil
	}
}
