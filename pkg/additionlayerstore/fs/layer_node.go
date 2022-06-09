package fs

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/containerd/containerd/snapshots/storage"
	"github.com/containerd/nydus-snapshotter/pkg/label"
	"syscall"

	"github.com/containerd/containerd/log"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/opencontainers/go-digest"
)

// layerNode is the node at <mountpoint>/<imageref>/<layerdigest>.
type layerNode struct {
	fusefs.Inode
	attr fuse.Attr
	fs   *fs

	refNode *refNode
	digest  digest.Digest
}

var _ = (fusefs.InodeEmbedder)((*layerNode)(nil))
var _ = (fusefs.NodeCreater)((*layerNode)(nil))
var _ = (fusefs.NodeLookuper)((*layerNode)(nil))

// Create marks this layer as "using".
// We don't use refnode.Mkdir because Mkdir event doesn't reach here if layernode already exists.
func (n *layerNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (node *fusefs.Inode, fh fusefs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	//if name == layerUseFile {
	//	current := n.fs.layerManager.use(n.refNode.ref, n.digest)
	//	log.G(ctx).WithField("refcounter", current).Infof("layer %v / %v is marked as USING", n.refnode.ref, n.digest)
	//}
	return nil, nil, 0, syscall.ENOENT
}

// Lookup routes to the target file stored in the pool, based on the specified file name.
func (n *layerNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	log.L.WithContext(ctx).Infof("layer node lookup name = %s", name)
	switch name {
	case layerInfoLink:
		info, err := n.fs.getLayerInfo(ctx, n.refNode.ref, n.digest)
		if err != nil {
			log.G(ctx).WithError(err).Warnf("failed to get layer info for %q: %q", name, n.digest)
			return nil, syscall.EIO
		}
		buf := new(bytes.Buffer)
		if err := json.NewEncoder(buf).Encode(&info); err != nil {
			log.G(ctx).WithError(err).Warnf("failed to encode layer info for %q: %q", name, n.digest)
			return nil, syscall.EIO
		}
		infoData := buf.Bytes()
		sAttr := defaultFileAttr(uint64(len(infoData)), &out.Attr)
		cn := &fusefs.MemRegularFile{Data: infoData}
		copyAttr(&cn.Attr, &out.Attr)
		return n.fs.newInodeWithID(ctx, func(ino uint32) fusefs.InodeEmbedder {
			out.Attr.Ino = uint64(ino)
			cn.Attr.Ino = uint64(ino)
			sAttr.Ino = uint64(ino)
			return n.NewInode(ctx, cn, sAttr)
		})
	case layerLink:
		n.fs.knownNodeMu.Lock()
		if lh, ok := n.fs.knownNode[n.refNode.ref.String()][n.digest.String()]; ok {
			var ao fuse.AttrOut
			if errno := lh.n.(fusefs.NodeGetattrer).Getattr(ctx, nil, &ao); errno != 0 {
				return nil, errno
			}
			copyAttr(&out.Attr, &ao.Attr)
			n.fs.knownNodeMu.Unlock()
			return n.NewInode(ctx, lh.n, fusefs.StableAttr{
				Mode: out.Attr.Mode,
				Ino:  out.Attr.Ino,
			}), 0
		}
		n.fs.knownNodeMu.Unlock()

		manifest, _, err := n.fs.refPool.loadRef(ctx, n.refNode.ref)
		if err != nil {
			return nil, syscall.EIO
		}
		for _, layer := range manifest.Layers {
			if layer.Digest == n.digest {
				_, metaOK := layer.Annotations[label.NydusMetaLayer]
				if metaOK {
					if metaOK {
						layer.Annotations[label.ImageRef] = n.refNode.ref.String()
						layer.Annotations[label.CRIDigest] = n.digest.String()

						err = n.fs.nydusFs.PrepareMetaLayer(ctx, storage.Snapshot{ID: n.digest.String()}, layer.Annotations)
						if err != nil {
							panic(err)
							return nil, syscall.EIO
						}

						err = n.fs.nydusFs.Mount(ctx, n.digest.String(), layer.Annotations)
						if err != nil {
							panic(err)
							return nil, syscall.EIO
						}

						return nil, syscall.EIO
					}
				}
			}
		}
		if err != nil {
			panic(err)
			return nil, syscall.EIO
		}
		return nil, syscall.ENOENT
	case layerUseFile:
		log.G(ctx).Debugf("\"use\" file is referred but return ENOENT for reference management")
		return nil, syscall.ENOENT
	default:
		log.G(ctx).Warnf("unknown filename %q", name)
		return nil, syscall.ENOENT
	}
}
