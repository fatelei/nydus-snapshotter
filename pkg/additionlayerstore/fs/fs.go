/*
 * Copyright (c) 2021. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"context"
	"fmt"
	"github.com/containerd/containerd/reference"
	"github.com/containerd/nydus-snapshotter/config"
	fs2 "github.com/containerd/nydus-snapshotter/pkg/filesystem/fs"
	"github.com/containerd/nydus-snapshotter/pkg/filesystem/nydus"
	"github.com/containerd/nydus-snapshotter/pkg/process"
	"github.com/containerd/nydus-snapshotter/pkg/services/keychain/dockerconfig"
	"github.com/containerd/nydus-snapshotter/pkg/services/resolver"
	"github.com/containerd/nydus-snapshotter/pkg/signature"
	"github.com/containerd/nydus-snapshotter/pkg/store"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd/log"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sync/singleflight"
)

const (
	defaultLinkMode = syscall.S_IFLNK | 0400 // -r--------
	defaultDirMode  = syscall.S_IFDIR | 0500 // dr-x------
	defaultFileMode = 0400                   // -r--------
	layerFileMode   = 0400                   // -r--------
	blockSize       = 4096

	poolLink      = "pool"
	layerLink     = "diff"
	blobLink      = "blob"
	layerInfoLink = "info"
	layerUseFile  = "use"

	fusermountBin = "fusermount"
)

// idMap manages uint32 IDs with automatic GC for releasable objects.
type idMap struct {
	m        map[uint32]releasable
	max      uint32
	mu       sync.Mutex
	cleanupG singleflight.Group
}

type releasable interface {
	releasable() bool
}

type fs struct {
	// nodeMap manages inode numbers for nodes other than nodes in layers
	// (i.e. nodes other than ones inside `diff` directories).
	// - inode number = [ 0 ][ uint32 ID ]
	nodeMap *idMap
	// layerMap manages upper bits of inode numbers for nodes inside layers.
	// - inode number = [ uint32 layer ID ][ uint32 number (unique inside `diff` directory) ]
	// inodes numbers of noeds inside each `diff` directory are prefixed by an unique uint32
	// so that they don't conflict with nodes outside `diff` directories.
	layerMap *idMap

	knownNode   map[string]map[string]*layerReleasable
	knownNodeMu sync.Mutex

	refPool *refPool
	nydusFs fs2.FileSystem
}

type layerReleasable struct {
	n        fusefs.InodeEmbedder
	released bool
	mu       sync.Mutex
}

func (lh *layerReleasable) releasable() bool {
	lh.mu.Lock()
	released := lh.released
	lh.mu.Unlock()
	return released && isForgotten(lh.n.EmbeddedInode())
}

func (lh *layerReleasable) release() {
	lh.mu.Lock()
	lh.released = true
	lh.mu.Unlock()
}

type inoReleasable struct {
	n fusefs.InodeEmbedder
}

func (r *inoReleasable) releasable() bool {
	return r.n.EmbeddedInode().Forgotten()
}

func Mount(ctx context.Context, mountPoint string, rootDir string, debug bool, cfg *config.Config) error {
	seconds := time.Second
	refPool, err := newRefPool(ctx, rootDir, resolver.RegistryHostsFromConfig([]resolver.Credential{dockerconfig.NewDockerconfigKeychain(ctx)}...))
	if err != nil {
		return err
	}

	verifier, err := signature.NewVerifier(cfg.PublicKeyFile, cfg.ValidateSignature)
	if err != nil {
		return err
	}

	db, err := store.NewDatabase(rootDir)
	if err != nil {
		return errors.Wrap(err, "failed to new database")
	}

	pm, err := process.NewManager(process.Opt{
		NydusdBinaryPath: cfg.NydusdBinaryPath,
		Database:         db,
		DaemonMode:       cfg.DaemonMode,
		CacheDir:         cfg.CacheDir,
	})
	if err != nil {
		return errors.Wrap(err, "failed to new process manager")
	}

	opts := []nydus.NewFSOpt{
		nydus.WithProcessManager(pm),
		nydus.WithNydusdBinaryPath(cfg.NydusdBinaryPath, cfg.DaemonMode),
		nydus.WithMeta(rootDir),
		nydus.WithDaemonConfig(cfg.DaemonCfg),
		nydus.WithVPCRegistry(cfg.ConvertVpcRegistry),
		nydus.WithVerifier(verifier),
		nydus.WithDaemonMode(cfg.DaemonMode),
		nydus.WithDaemonBackend(cfg.DaemonBackend),
		nydus.WithLogLevel(cfg.LogLevel),
		nydus.WithLogDir(cfg.LogDir),
		nydus.WithLogToStdout(cfg.LogToStdout),
		nydus.WithNydusdThreadNum(cfg.NydusdThreadNum),
	}

	nydusFs, err := nydus.NewFileSystem(ctx, opts...)
	if err != nil {
		return errors.Wrap(err, "failed to initialize nydus filesystem")
	}


	rawFS := fusefs.NewNodeFS(&rootNode{
		fs: &fs{
			nodeMap:  new(idMap),
			layerMap: new(idMap),
			refPool:  refPool,
			nydusFs: nydusFs,
		},
	}, &fusefs.Options{
		AttrTimeout:     &seconds,
		EntryTimeout:    &seconds,
		NullPermissions: true,
	})
	mountOpts := &fuse.MountOptions{
		AllowOther: true, // allow users other than root&mounter to access fs
		FsName:     "nydusstore",
		Debug:      debug,
	}
	if _, err := exec.LookPath(fusermountBin); err == nil {
		mountOpts.Options = []string{"suid"} // option for fusermount; allow setuid inside container
	} else {
		log.L.WithError(err).Debugf("%s not installed; trying direct mount", fusermountBin)
		mountOpts.DirectMount = true
	}
	server, err := fuse.NewServer(rawFS, fmt.Sprintf(mountPoint, "store"), mountOpts)
	if err != nil {
		return err
	}
	go server.Serve()
	return server.WaitMount()
}

func (fs *fs) newInodeWithID(ctx context.Context, p func(uint32) fusefs.InodeEmbedder) (*fusefs.Inode, syscall.Errno) {
	var ino fusefs.InodeEmbedder
	if err := fs.nodeMap.add(func(id uint32) (releasable, error) {
		ino = p(id)
		return &inoReleasable{ino}, nil
	}); err != nil || ino == nil {
		log.L.WithContext(ctx).WithError(err).Debug("cannot generate ID")
		return nil, syscall.EIO
	}
	return ino.EmbeddedInode(), 0
}

func (fs *fs) getLayerInfo(ctx context.Context, refspec reference.Spec, dgst digest.Digest) (Layer, error) {
	manifest, config, err := fs.refPool.loadRef(ctx, refspec)
	if err != nil {
		return Layer{}, fmt.Errorf("failed to get manifest and config: %w", err)
	}
	return genLayerInfo(ctx, dgst, manifest, config)
}

// add reserves an unique uint32 object for the provided releasable object.
// when that object become releasable, that ID will be reused for other objects.
func (m *idMap) add(p func(uint32) (releasable, error)) error {
	m.cleanupG.Do("cleanup", func() (interface{}, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		max := uint32(0)
		for i := uint32(0); i <= m.max; i++ {
			if e, ok := m.m[i]; ok {
				if e.releasable() {
					delete(m.m, i)
				} else {
					max = i
				}
			}
		}
		m.max = max
		return nil, nil
	})

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.m == nil {
		m.m = make(map[uint32]releasable)
	}

	for i := uint32(0); i <= ^uint32(0); i++ {
		if i == 0 || i == 1 {
			continue
		}
		log.L.Infof("current ino = %d", i)
		e, ok := m.m[i]
		if !ok || e.releasable() {
			r, err := p(i)
			if err != nil {
				return err
			}
			if m.max < i {
				m.max = i
			}
			m.m[i] = r
			return nil
		}
	}
	return fmt.Errorf("no ID is usable")
}
