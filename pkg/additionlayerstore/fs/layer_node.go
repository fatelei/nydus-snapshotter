package fs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/containerd/nydus-snapshotter/pkg/additionlayerstore/layer"
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
	if name == layerUseFile {
		current := n.fs.layManager.Use(n.refNode.ref, n.digest)
		log.G(ctx).WithField("refcounter", current).Infof("layer %v / %v is marked as USING", n.refNode.ref, n.digest)
	}
	return nil, nil, 0, syscall.ENOENT
}

// Lookup routes to the target file stored in the pool, based on the specified file name.
func (n *layerNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	log.L.WithContext(ctx).Infof("layer node lookup name = %s", name)
	switch name {
	case layerInfoLink:
		info, err := n.fs.layManager.GetLayerInfo(ctx, n.refNode.ref, n.digest)
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
	case layerLink, blobLink:
		if name == layerLink {
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
		}

		l, err := n.fs.layManager.ResolverMetaLayer(ctx, n.refNode.ref, n.digest)
		if err != nil {
			return nil, syscall.EIO
		}

		if name == blobLink {
			sAttr := layerToAttr(l, &out.Attr)
			cn := &blobNode{l: l}
			copyAttr(&cn.attr, &out.Attr)
			return n.fs.newInodeWithID(ctx, func(ino uint32) fusefs.InodeEmbedder {
				out.Attr.Ino = uint64(ino)
				cn.attr.Ino = uint64(ino)
				sAttr.Ino = uint64(ino)
				return n.NewInode(ctx, cn, sAttr)
			})
		}

		var cn *fusefs.Inode
		var errno syscall.Errno
		err = n.fs.layerMap.add(func(id uint32) (releasable, error) {
			root, err := layer.NewNode(n.digest, id, layer.OverlayOpaqueAll)
			if err != nil {
				return nil, err
			}

			var ao fuse.AttrOut
			errno = root.(fusefs.NodeGetattrer).Getattr(ctx, nil, &ao)
			if errno != 0 {
				return nil, fmt.Errorf("failed to get root node: %v", errno)
			}

			copyAttr(&out.Attr, &ao.Attr)
			cn = n.NewInode(ctx, root, fusefs.StableAttr{
				Mode: out.Attr.Mode,
				Ino:  out.Attr.Ino,
			})

			rr := &layerReleasable{n: root}
			n.fs.knownNodeMu.Lock()
			if n.fs.knownNode == nil {
				n.fs.knownNode = make(map[string]map[string]*layerReleasable)
			}
			if n.fs.knownNode[n.refNode.ref.String()] == nil {
				n.fs.knownNode[n.refNode.ref.String()] = make(map[string]*layerReleasable)
			}
			n.fs.knownNode[n.refNode.ref.String()][n.digest.String()] = rr
			n.fs.knownNodeMu.Unlock()
			return rr, nil
		})
		if err != nil || errno != 0 {
			if errno == 0 {
				errno = syscall.EIO
			}
			return nil, errno
		}
		return cn, 0
	case layerUseFile:
		log.G(ctx).Debugf("\"use\" file is referred but return ENOENT for reference management")
		return nil, syscall.ENOENT
	default:
		log.G(ctx).Warnf("unknown filename %q", name)
		return nil, syscall.ENOENT
	}
}
