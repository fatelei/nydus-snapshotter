package layer

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	fusefs "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/opencontainers/go-digest"
	"golang.org/x/sys/unix"
)

const (
	blockSize         = 4096
	whiteoutPrefix    = ".wh."
	whiteoutOpaqueDir = whiteoutPrefix + whiteoutPrefix + ".opq"
	opaqueXattrValue  = "y"
	statFileMode      = syscall.S_IFREG | 0400 // -r--------
	stateDirMode      = syscall.S_IFDIR | 0500 // dr-x------
)

type OverlayOpaqueType int

const (
	OverlayOpaqueAll OverlayOpaqueType = iota
	OverlayOpaqueTrusted
	OverlayOpaqueUser
)

var opaqueXattrs = map[OverlayOpaqueType][]string{
	OverlayOpaqueAll:     {"trusted.overlay.opaque", "user.overlay.opaque"},
	OverlayOpaqueTrusted: {"trusted.overlay.opaque"},
	OverlayOpaqueUser:    {"user.overlay.opaque"},
}

type attr struct {
	// Size, for regular files, is the logical size of the file.
	Size int64

	// ModTime is the modification time of the node.
	ModTime time.Time

	// LinkName, for symlinks, is the link target.
	LinkName string

	// Mode is the permission and mode bits.
	Mode os.FileMode

	// UID is the user ID of the owner.
	UID int

	// GID is the group ID of the owner.
	GID int

	// DevMajor is the major device number for device.
	DevMajor int

	// DevMinor is the major device number for device.
	DevMinor int

	// Xattrs are the extended attribute for the node.
	Xattrs map[string][]byte

	// NumLink is the number of names pointing to this node.
	NumLink int
}

func NewNode(layerDigest digest.Digest, baseInode uint32, opaque OverlayOpaqueType) (fusefs.InodeEmbedder, error) {
	//rootID := r.Metadata().RootID()
	//rootAttr, err := r.Metadata().GetAttr(rootID)
	//if err != nil {
	//	return nil, err
	//}
	opq, ok := opaqueXattrs[opaque]
	if !ok {
		return nil, fmt.Errorf("Unknown overlay opaque type")
	}
	ffs := &fs{
		layerDigest:  layerDigest,
		baseInode:    baseInode,
		rootID:       baseInode,
		opaqueXattrs: opq,
	}
	return &node{
		id:   baseInode,
		fs:   ffs,
	}, nil
}

// fs contains global metadata used by nodes
type fs struct {
	layerDigest  digest.Digest
	baseInode    uint32
	rootID       uint32
	opaqueXattrs []string
}

func (fs *fs) inodeOfState() uint64 {
	return (uint64(fs.baseInode) << 32) | 1 // reserved
}

func (fs *fs) inodeOfStatFile() uint64 {
	return (uint64(fs.baseInode) << 32) | 2 // reserved
}

func (fs *fs) inodeOfID(id uint32) (uint64, error) {
	// 0 is reserved by go-fuse 1 and 2 are reserved by the state dir
	if id > ^uint32(0)-3 {
		return 0, fmt.Errorf("too many inodes")
	}
	return (uint64(fs.baseInode) << 32) | uint64(3+id), nil
}

// node is a filesystem inode abstraction.
type node struct {
	fusefs.Inode
	fs         *fs
	id         uint32
	attr       attr
	ents       []fuse.DirEntry
	entsCached bool
}

func (n *node) isRootNode() bool {
	return n.id == n.fs.rootID
}

func (n *node) isOpaque() bool {
	//if _, _, err := n.fs.r.Metadata().GetChild(n.id, whiteoutOpaqueDir); err == nil {
	//	return true
	//}
	return false
}

var _ = (fusefs.InodeEmbedder)((*node)(nil))

var _ = (fusefs.NodeReaddirer)((*node)(nil))

func (n *node) Readdir(ctx context.Context) (fusefs.DirStream, syscall.Errno) {
	ents, errno := n.readdir()
	if errno != 0 {
		return nil, errno
	}
	return fusefs.NewListDirStream(ents), 0
}

func (n *node) readdir() ([]fuse.DirEntry, syscall.Errno) {
	if n.entsCached {
		return n.ents, 0
	}

	//isRoot := n.isRootNode()

	var ents []fuse.DirEntry
	whiteouts := map[string]uint32{}
	normalEnts := map[string]bool{}
	//var lastErr error
	//if err := n.fs.r.Metadata().ForeachChild(n.id, func(name string, id uint32, mode os.FileMode) bool {
	//
	//	// We don't want to show prefetch landmarks in "/".
	//	if isRoot && (name == estargz.PrefetchLandmark || name == estargz.NoPrefetchLandmark) {
	//		return true
	//	}
	//
	//	// We don't want to show whiteouts.
	//	if strings.HasPrefix(name, whiteoutPrefix) {
	//		if name == whiteoutOpaqueDir {
	//			return true
	//		}
	//		// Add the overlayfs-compiant whiteout later.
	//		whiteouts[name] = id
	//		return true
	//	}
	//
	//	// This is a normal entry.
	//	normalEnts[name] = true
	//	ino, err := n.fs.inodeOfID(id)
	//	if err != nil {
	//		lastErr = err
	//		return false
	//	}
	//	ents = append(ents, fuse.DirEntry{
	//		Mode: fileModeToSystemMode(mode),
	//		Name: name,
	//		Ino:  ino,
	//	})
	//	return true
	//}); err != nil || lastErr != nil {
	//	return nil, syscall.EIO
	//}

	// Append whiteouts if no entry replaces the target entry in the lower layer.
	for w, id := range whiteouts {
		if !normalEnts[w[len(whiteoutPrefix):]] {
			ino, err := n.fs.inodeOfID(id)
			if err != nil {
				return nil, syscall.EIO
			}
			ents = append(ents, fuse.DirEntry{
				Mode: syscall.S_IFCHR,
				Name: w[len(whiteoutPrefix):],
				Ino:  ino,
			})

		}
	}

	// Avoid undeterministic order of entries on each call
	sort.Slice(ents, func(i, j int) bool {
		return ents[i].Name < ents[j].Name
	})
	n.ents, n.entsCached = ents, true // cache it

	return ents, 0
}

var _ = (fusefs.NodeLookuper)((*node)(nil))

func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {

	isRoot := n.isRootNode()

	// We don't want to show prefetch landmarks in "/".
	if isRoot {
		return nil, syscall.ENOENT
	}

	// We don't want to show whiteouts.
	if strings.HasPrefix(name, whiteoutPrefix) {
		return nil, syscall.ENOENT
	}

	// lookup on memory nodes
	if cn := n.GetChild(name); cn != nil {
		switch tn := cn.Operations().(type) {
		case *node:
			ino, err := n.fs.inodeOfID(tn.id)
			if err != nil {
				return nil, syscall.EIO
			}
			entryToAttr(ino, tn.attr, &out.Attr)
		case *whiteout:
			ino, err := n.fs.inodeOfID(tn.id)
			if err != nil {
				return nil, syscall.EIO
			}
			entryToAttr(ino, tn.attr, &out.Attr)
		default:
			return nil, syscall.EIO
		}
		return cn, 0
	}

	// early return if this entry doesn't exist
	if n.entsCached {
		var found bool
		for _, e := range n.ents {
			if e.Name == name {
				found = true
			}
		}
		if !found {
			return nil, syscall.ENOENT
		}
	}
	return nil, syscall.EIO
	//id, ce, err := n.fs.r.Metadata().GetChild(n.id, name)
	//if err != nil {
	//	// If the entry exists as a whiteout, show an overlayfs-styled whiteout node.
	//	if whID, wh, err := n.fs.r.Metadata().GetChild(n.id, fmt.Sprintf("%s%s", whiteoutPrefix, name)); err == nil {
	//		ino, err := n.fs.inodeOfID(whID)
	//		if err != nil {
	//			return nil, syscall.EIO
	//		}
	//		return n.NewInode(ctx, &whiteout{
	//			id:   whID,
	//			fs:   n.fs,
	//			attr: wh,
	//		}, entryToWhAttr(ino, wh, &out.Attr)), 0
	//	}
	//	n.readdir() // This code path is very expensive. Cache child entries here so that the next call don't reach here.
	//	return nil, syscall.ENOENT
	//}
	//
	//ino, err := n.fs.inodeOfID(id)
	//if err != nil {
	//	return nil, syscall.EIO
	//}
	//return n.NewInode(ctx, &node{
	//	id:   id,
	//	fs:   n.fs,
	//	attr: ce,
	//}, entryToAttr(ino, ce, &out.Attr)), 0
}

var _ = (fusefs.NodeOpener)((*node)(nil))

func (n *node) Open(ctx context.Context, flags uint32) (fh fusefs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	return nil, 0, syscall.EIO
	//ra, err := n.fs.r.OpenFile(n.id)
	//if err != nil {
	//	return nil, 0, syscall.EIO
	//}
	//return &file{
	//	n:  n,
	//	ra: ra,
	//}, fuse.FOPEN_KEEP_CACHE, 0
}

var _ = (fusefs.NodeGetattrer)((*node)(nil))

func (n *node) Getattr(ctx context.Context, f fusefs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	ino, err := n.fs.inodeOfID(n.id)
	if err != nil {
		return syscall.EIO
	}
	entryToAttr(ino, n.attr, &out.Attr)
	return 0
}

var _ = (fusefs.NodeGetxattrer)((*node)(nil))

func (n *node) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	ent := n.attr
	opq := n.isOpaque()
	for _, opaqueXattr := range n.fs.opaqueXattrs {
		if attr == opaqueXattr && opq {
			// This node is an opaque directory so give overlayfs-compliant indicator.
			if len(dest) < len(opaqueXattrValue) {
				return uint32(len(opaqueXattrValue)), syscall.ERANGE
			}
			return uint32(copy(dest, opaqueXattrValue)), 0
		}
	}
	if v, ok := ent.Xattrs[attr]; ok {
		if len(dest) < len(v) {
			return uint32(len(v)), syscall.ERANGE
		}
		return uint32(copy(dest, v)), 0
	}
	return 0, syscall.ENODATA
}

var _ = (fusefs.NodeListxattrer)((*node)(nil))

func (n *node) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	ent := n.attr
	opq := n.isOpaque()
	var attrs []byte
	if opq {
		// This node is an opaque directory so add overlayfs-compliant indicator.
		for _, opaqueXattr := range n.fs.opaqueXattrs {
			attrs = append(attrs, []byte(opaqueXattr+"\x00")...)
		}
	}
	for k := range ent.Xattrs {
		attrs = append(attrs, []byte(k+"\x00")...)
	}
	if len(dest) < len(attrs) {
		return uint32(len(attrs)), syscall.ERANGE
	}
	return uint32(copy(dest, attrs)), 0
}

var _ = (fusefs.NodeReadlinker)((*node)(nil))

func (n *node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	ent := n.attr
	return []byte(ent.LinkName), 0
}

var _ = (fusefs.NodeStatfser)((*node)(nil))

func (n *node) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	defaultStatfs(out)
	return 0
}

// file is a file abstraction which implements file handle in go-fuse.
type file struct {
	n  *node
	ra io.ReaderAt
}

var _ = (fusefs.FileReader)((*file)(nil))

func (f *file) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	n, err := f.ra.ReadAt(dest, off)
	if err != nil && err != io.EOF {
		return nil, syscall.EIO
	}
	return fuse.ReadResultData(dest[:n]), 0
}

var _ = (fusefs.FileGetattrer)((*file)(nil))

func (f *file) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	ino, err := f.n.fs.inodeOfID(f.n.id)
	if err != nil {
		return syscall.EIO
	}
	entryToAttr(ino, f.n.attr, &out.Attr)
	return 0
}

// whiteout is a whiteout abstraction compliant to overlayfs.
type whiteout struct {
	fusefs.Inode
	id   uint32
	fs   *fs
	attr attr
}

var _ = (fusefs.NodeGetattrer)((*whiteout)(nil))

func (w *whiteout) Getattr(ctx context.Context, f fusefs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	ino, err := w.fs.inodeOfID(w.id)
	if err != nil {
		return syscall.EIO
	}
	entryToWhAttr(ino, w.attr, &out.Attr)
	return 0
}

var _ = (fusefs.NodeStatfser)((*whiteout)(nil))

func (w *whiteout) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	defaultStatfs(out)
	return 0
}

// entryToAttr converts metadata.Attr to go-fuse's Attr.
func entryToAttr(ino uint64, e attr, out *fuse.Attr) fusefs.StableAttr {
	out.Ino = ino
	out.Size = uint64(e.Size)
	if e.Mode&os.ModeSymlink != 0 {
		out.Size = uint64(len(e.LinkName))
	}
	out.Blksize = blockSize
	out.Blocks = out.Size / uint64(out.Blksize)
	if out.Size%uint64(out.Blksize) > 0 {
		out.Blocks++
	}
	mtime := e.ModTime
	out.SetTimes(nil, &mtime, nil)
	out.Mode = fileModeToSystemMode(e.Mode)
	out.Owner = fuse.Owner{Uid: uint32(e.UID), Gid: uint32(e.GID)}
	out.Rdev = uint32(unix.Mkdev(uint32(e.DevMajor), uint32(e.DevMinor)))
	out.Nlink = uint32(e.NumLink)
	if out.Nlink == 0 {
		out.Nlink = 1 // zero "NumLink" means one.
	}
	out.Padding = 0 // TODO

	return fusefs.StableAttr{
		Mode: out.Mode,
		Ino:  out.Ino,
		// NOTE: The inode number is unique throughout the lifetime of
		// this filesystem so we don't consider about generation at this
		// moment.
	}
}

// entryToWhAttr converts metadata.Attr to go-fuse's Attr of whiteouts.
func entryToWhAttr(ino uint64, e attr, out *fuse.Attr) fusefs.StableAttr {
	out.Ino = ino
	out.Size = 0
	out.Blksize = blockSize
	out.Blocks = 0
	mtime := e.ModTime
	out.SetTimes(nil, &mtime, nil)
	out.Mode = syscall.S_IFCHR
	out.Owner = fuse.Owner{Uid: 0, Gid: 0}
	out.Rdev = uint32(unix.Mkdev(0, 0))
	out.Nlink = 1
	out.Padding = 0 // TODO

	return fusefs.StableAttr{
		Mode: out.Mode,
		Ino:  out.Ino,
		// NOTE: The inode number is unique throughout the lifetime of
		// this filesystem so we don't consider about generation at this
		// moment.
	}
}

// stateToAttr converts state directory to go-fuse's Attr.
func (fs *fs) stateToAttr(out *fuse.Attr) fusefs.StableAttr {
	out.Ino = fs.inodeOfState()
	out.Size = 0
	out.Blksize = blockSize
	out.Blocks = 0
	out.Nlink = 1

	// root can read and open it (dr-x------ root root).
	out.Mode = stateDirMode
	out.Owner = fuse.Owner{Uid: 0, Gid: 0}

	// dummy
	out.Mtime = 0
	out.Mtimensec = 0
	out.Rdev = 0
	out.Padding = 0

	return fusefs.StableAttr{
		Mode: out.Mode,
		Ino:  out.Ino,
		// NOTE: The inode number is unique throughout the lifetime of
		// this filesystem so we don't consider about generation at this
		// moment.
	}
}

// statFileToAttr converts stat file to go-fuse's Attr.
// func statFileToAttr(id uint64, sf *statFile, size uint64, out *fuse.Attr) fusefs.StableAttr {
func (fs *fs) statFileToAttr(size uint64, out *fuse.Attr) fusefs.StableAttr {
	out.Ino = fs.inodeOfStatFile()
	out.Size = size
	out.Blksize = blockSize
	out.Blocks = out.Size / uint64(out.Blksize)
	out.Nlink = 1

	// Root can read it ("-r-------- root root").
	out.Mode = statFileMode
	out.Owner = fuse.Owner{Uid: 0, Gid: 0}

	// dummy
	out.Mtime = 0
	out.Mtimensec = 0
	out.Rdev = 0
	out.Padding = 0

	return fusefs.StableAttr{
		Mode: out.Mode,
		Ino:  out.Ino,
		// NOTE: The inode number is unique throughout the lifetime of
		// this filesystem so we don't consider about generation at this
		// moment.
	}
}

func fileModeToSystemMode(m os.FileMode) uint32 {
	// Permission bits
	res := uint32(m & os.ModePerm)

	// File type bits
	switch m & os.ModeType {
	case os.ModeDevice:
		res |= syscall.S_IFBLK
	case os.ModeDevice | os.ModeCharDevice:
		res |= syscall.S_IFCHR
	case os.ModeDir:
		res |= syscall.S_IFDIR
	case os.ModeNamedPipe:
		res |= syscall.S_IFIFO
	case os.ModeSymlink:
		res |= syscall.S_IFLNK
	case os.ModeSocket:
		res |= syscall.S_IFSOCK
	default: // regular file.
		res |= syscall.S_IFREG
	}

	// suid, sgid, sticky bits
	if m&os.ModeSetuid != 0 {
		res |= syscall.S_ISUID
	}
	if m&os.ModeSetgid != 0 {
		res |= syscall.S_ISGID
	}
	if m&os.ModeSticky != 0 {
		res |= syscall.S_ISVTX
	}

	return res
}

func defaultStatfs(stat *fuse.StatfsOut) {

	// http://man7.org/linux/man-pages/man2/statfs.2.html
	stat.Blocks = 0 // dummy
	stat.Bfree = 0
	stat.Bavail = 0
	stat.Files = 0 // dummy
	stat.Ffree = 0
	stat.Bsize = blockSize
	stat.NameLen = 1<<32 - 1
	stat.Frsize = blockSize
	stat.Padding = 0
	stat.Spare = [6]uint32{}
}
