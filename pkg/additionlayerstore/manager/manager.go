package manager

import (
	"context"
	"fmt"
	"github.com/opencontainers/go-digest"

	"os"
	"path/filepath"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/reference"
	"github.com/containerd/containerd/snapshots/storage"
	"github.com/containerd/nydus-snapshotter/config"
	"github.com/containerd/nydus-snapshotter/pkg/additionlayerstore/source"
	fs2 "github.com/containerd/nydus-snapshotter/pkg/filesystem/fs"
	"github.com/containerd/nydus-snapshotter/pkg/filesystem/nydus"
	"github.com/containerd/nydus-snapshotter/pkg/label"
	"github.com/containerd/nydus-snapshotter/pkg/process"
	"github.com/containerd/nydus-snapshotter/pkg/signature"
	"github.com/containerd/nydus-snapshotter/pkg/store"
	"github.com/containerd/nydus-snapshotter/pkg/utils/namedmutex"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"strings"
	"sync"
)

const (
	remoteSnapshotLogKey = "remote-snapshot-prepared"
	prepareSucceeded     = "true"
	prepareFailed        = "false"

	defaultMaxConcurrency = 2
)

func NewLayerManager(ctx context.Context, rootDir string, hosts source.RegistryHosts, cfg *config.Config) (*LayerManager, error) {
	verifier, err := signature.NewVerifier(cfg.PublicKeyFile, cfg.ValidateSignature)
	if err != nil {
		return nil, err
	}

	db, err := store.NewDatabase(rootDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to new database")
	}

	pm, err := process.NewManager(process.Opt{
		NydusdBinaryPath: cfg.NydusdBinaryPath,
		Database:         db,
		DaemonMode:       cfg.DaemonMode,
		CacheDir:         cfg.CacheDir,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to new process manager")
	}

	if err = os.Mkdir(filepath.Join(rootDir, "snapshots"), 0700); err != nil && !os.IsExist(err) {
		return nil, err
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
		return nil, errors.Wrap(err, "failed to initialize nydus filesystem")
	}

	refPool, err := newRefPool(ctx, rootDir, hosts)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("failed to setup resolver: %w", err)
	}
	return &LayerManager{
		refPool:     refPool,
		hosts:       hosts,
		resolveLock: new(namedmutex.NamedMutex),
		refCounter:  make(map[string]map[string]int),
		nydusFs:     nydusFs,
	}, nil
}

// LayerManager manages layers of images and their resource lifetime.
type LayerManager struct {
	refPool *refPool
	hosts   source.RegistryHosts

	prefetchSize        int64
	noprefetch          bool
	noBackgroundFetch   bool
	allowNoVerification bool
	disableVerification bool
	resolveLock         *namedmutex.NamedMutex

	refCounter map[string]map[string]int

	nydusFs fs2.FileSystem

	mu sync.Mutex
}

func (r *LayerManager) GetLayerInfo(ctx context.Context, refspec reference.Spec, dgst digest.Digest) (Layer, error) {
	manifest, config, err := r.refPool.loadRef(ctx, refspec)
	if err != nil {
		return Layer{}, fmt.Errorf("failed to get manifest and config: %w", err)
	}
	return genLayerInfo(ctx, dgst, manifest, config)
}

func (r *LayerManager) ResolverMetaLayer(ctx context.Context, refspec reference.Spec, digest digest.Digest) error {
	// get manifest from cache.
	manifest, _, err := r.refPool.loadRef(ctx, refspec)
	if err != nil {
		return fmt.Errorf("failed to get manifest and config: %w", err)
	}
	var target ocispec.Descriptor
	var found bool
	for _, l := range manifest.Layers {
		if l.Digest == digest {
			l := l
			found = true
			target = l
			break
		}
	}
	if !found {
		return fmt.Errorf("unknown digest %v for ref %q", target, refspec.String())
	}

	if _, ok := target.Annotations[label.NydusMetaLayer]; ok {
		target.Annotations[label.ImageRef] = refspec.String()
		target.Annotations[label.CRIDigest] = target.Digest.String()
		err = r.nydusFs.PrepareMetaLayer(ctx, storage.Snapshot{ID: refspec.String()}, target.Annotations)
		if err != nil {
			log.G(ctx).Errorf("download snapshot files failed: %+v", err)
			return err
		}

		nydusFs, ok := r.nydusFs.(*nydus.NydusFilesystem)
		if ok {
			err = nydusFs.MountDiff(ctx, refspec.String(), digest.String(), target.Annotations)
			if err != nil {
				log.G(ctx).Errorf("mount diff file has error: %+v", err)
				return err
			}
		}
	}
	return nil
}

func (r *LayerManager) Release(ctx context.Context, refspec reference.Spec, dgst digest.Digest) (int, error) {
	r.refPool.release(refspec)

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.refCounter == nil || r.refCounter[refspec.String()] == nil {
		return 0, fmt.Errorf("ref %q not tracked", refspec.String())
	} else if _, ok := r.refCounter[refspec.String()][dgst.String()]; !ok {
		return 0, fmt.Errorf("layer %q/%q not tracked", refspec.String(), dgst.String())
	}
	r.refCounter[refspec.String()][dgst.String()]--
	i := r.refCounter[refspec.String()][dgst.String()]
	if i <= 0 {
		// No reference to this layer. release it.
		delete(r.refCounter, dgst.String())
		if len(r.refCounter[refspec.String()]) == 0 {
			delete(r.refCounter, refspec.String())
		}
		log.G(ctx).WithField("refcounter", i).Infof("layer %v/%v is released due to no reference", refspec, dgst)
	}
	return i, nil
}

func (r *LayerManager) Use(refspec reference.Spec, dgst digest.Digest) int {
	r.refPool.use(refspec)

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.refCounter == nil {
		r.refCounter = make(map[string]map[string]int)
	}
	if r.refCounter[refspec.String()] == nil {
		r.refCounter[refspec.String()] = make(map[string]int)
	}
	if _, ok := r.refCounter[refspec.String()][dgst.String()]; !ok {
		r.refCounter[refspec.String()][dgst.String()] = 1
		return 1
	}
	r.refCounter[refspec.String()][dgst.String()]++
	return r.refCounter[refspec.String()][dgst.String()]
}

func (r *LayerManager) RefRoot() string {
	return r.refPool.root()
}

func colon2dash(s string) string {
	return strings.ReplaceAll(s, ":", "-")
}

// Layer represents the layer information. Format is compatible to the one required by
// "additional layer store" of github.com/containers/storage.
type Layer struct {
	CompressedDigest   digest.Digest `json:"compressed-diff-digest,omitempty"`
	CompressedSize     int64         `json:"compressed-size,omitempty"`
	UncompressedDigest digest.Digest `json:"diff-digest,omitempty"`
	UncompressedSize   int64         `json:"diff-size,omitempty"`
	CompressionType    int           `json:"compression,omitempty"`
	ReadOnly           bool          `json:"-"`
}

// Defined in https://github.com/containers/storage/blob/b64e13a1afdb0bfed25601090ce4bbbb1bc183fc/pkg/archive/archive.go#L108-L119
const gzipTypeMagicNum = 2

func genLayerInfo(ctx context.Context, dgst digest.Digest, manifest ocispec.Manifest, config ocispec.Image) (Layer, error) {
	if len(manifest.Layers) != len(config.RootFS.DiffIDs) {
		return Layer{}, fmt.Errorf(
			"len(manifest.Layers) != len(config.Rootfs): %d != %d",
			len(manifest.Layers), len(config.RootFS.DiffIDs))
	}
	var (
		layerIndex = -1
	)
	for i, l := range manifest.Layers {
		if l.Digest == dgst {
			layerIndex = i
		}
	}
	if layerIndex == -1 {
		return Layer{}, fmt.Errorf("layer %q not found in the manifest", dgst.String())
	}
	var uncompressedSize int64
	return Layer{
		CompressedDigest:   manifest.Layers[layerIndex].Digest,
		CompressedSize:     manifest.Layers[layerIndex].Size,
		UncompressedDigest: config.RootFS.DiffIDs[layerIndex],
		UncompressedSize:   uncompressedSize,
		CompressionType:    gzipTypeMagicNum,
		ReadOnly:           true,
	}, nil
}
