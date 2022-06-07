package fs

import (
	"context"
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
			panic(err)
			return nil, syscall.EIO
		}

		log.L.WithContext(ctx).Infof("manifest is %+v", manifest)
		return nil, syscall.ENOENT
	case layerUseFile:
		log.G(ctx).Debugf("\"use\" file is referred but return ENOENT for reference management")
		return nil, syscall.ENOENT
	default:
		log.G(ctx).Warnf("unknown filename %q", name)
		return nil, syscall.ENOENT
	}
}
