package source

import (
	"github.com/containerd/containerd/reference"
	"github.com/containerd/containerd/remotes/docker"
)

type RegistryHosts func(reference.Spec) ([]docker.RegistryHost, error)
