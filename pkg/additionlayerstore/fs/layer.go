package fs

import (
	"context"
	"fmt"

	"github.com/containerd/containerd/log"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

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
	//var err error
	//if uncompressedSizeStr, ok := manifest.Layers[layerIndex].Annotations[estargz.StoreUncompressedSizeAnnotation]; ok {
	//	uncompressedSize, err = strconv.ParseInt(uncompressedSizeStr, 10, 64)
	//	if err != nil {
	//		log.G(ctx).WithError(err).Warnf("layer %q has invalid uncompressed size; exposing incomplete layer info", dgst.String())
	//	}
	//} else {
	//	log.G(ctx).Warnf("layer %q doesn't have uncompressed size; exposing incomplete layer info", dgst.String())
	//}
	if uncompressedSize == 0 {
		log.G(ctx).Warnf("layer %q doesn't have uncompressed size; exposing incomplete layer info", dgst.String())
	}

	return Layer{
		CompressedDigest:   manifest.Layers[layerIndex].Digest,
		CompressedSize:     manifest.Layers[layerIndex].Size,
		UncompressedDigest: config.RootFS.DiffIDs[layerIndex],
		UncompressedSize:   uncompressedSize,
		CompressionType:    gzipTypeMagicNum,
		ReadOnly:           true,
	}, nil
}
