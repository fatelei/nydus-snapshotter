package fs

import (
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func isForgotten(n *fusefs.Inode) bool {
	if !n.Forgotten() {
		return false
	}
	for _, cn := range n.Children() {
		if !isForgotten(cn) {
			return false
		}
	}
	return true
}

func copyAttr(dest, src *fuse.Attr) {
	dest.Ino = src.Ino
	dest.Size = src.Size
	dest.Blocks = src.Blocks
	dest.Atime = src.Atime
	dest.Mtime = src.Mtime
	dest.Ctime = src.Ctime
	dest.Atimensec = src.Atimensec
	dest.Mtimensec = src.Mtimensec
	dest.Ctimensec = src.Ctimensec
	dest.Mode = src.Mode
	dest.Nlink = src.Nlink
	dest.Owner = src.Owner
	dest.Rdev = src.Rdev
	dest.Blksize = src.Blksize
	dest.Padding = src.Padding
}

// layerToAttr covert layer to fuse attribute.
func layerToAttr(l *ocispec.Descriptor, out *fuse.Attr) fusefs.StableAttr {
	out.Size = uint64(l.Size)
	out.Blksize = blockSize
	out.Blocks = out.Size / uint64(out.Blksize)
	if out.Size%uint64(out.Blksize) > 0 {
		out.Blocks++
	}
	out.Nlink = 1
	out.Mode = layerFileMode
	out.Owner = fuse.Owner{Uid: 0, Gid: 0}

	return fusefs.StableAttr{
		Mode: out.Mode,
	}
}

// defaultFileAttr generate default file attribute.
func defaultFileAttr(size uint64, out *fuse.Attr) fusefs.StableAttr {
	out.Size = size
	out.Blksize = blockSize
	out.Blocks = out.Size / uint64(out.Blksize)
	if out.Size%uint64(out.Blksize) > 0 {
		out.Blocks++
	}
	out.Nlink = 1
	out.Mode = defaultFileMode
	out.Owner = fuse.Owner{Uid: 0, Gid: 0}
	return fusefs.StableAttr{
		Mode: out.Mode,
	}
}

// defaultDirAttr generate default directory attribute.
func defaultDirAttr(out *fuse.Attr) fusefs.StableAttr {
	out.Size = 0
	out.Mode = defaultDirMode
	out.Owner = fuse.Owner{Uid: 0, Gid: 0}
	return fusefs.StableAttr{
		Mode: out.Mode,
	}
}

// defaultLinkAttr generate default link attribute.
func defaultLinkAttr(out *fuse.Attr) fusefs.StableAttr {
	out.Size = 0
	out.Mode = defaultLinkMode
	out.Owner = fuse.Owner{Uid: 0, Gid: 0}
	return fusefs.StableAttr{
		Mode: out.Mode,
	}
}
