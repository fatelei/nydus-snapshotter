/*
 * Copyright (c) 2021. Alibaba Cloud. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/containerd/containerd/reference/docker"
	"github.com/containerd/nydus-snapshotter/pkg/auth"
	"github.com/google/go-containerregistry/pkg/name"
	retryablehttp "github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"

	"github.com/containerd/nydus-snapshotter/pkg/utils/registry"
)

const HTTPClientTimeOut = time.Second * 30

type Resolver struct {
	transport http.RoundTripper
}

func NewResolver() *Resolver {
	resolver := Resolver{
		transport: http.DefaultTransport,
	}
	return &resolver
}

func (r *Resolver) Resolve(ref, digest string, labels map[string]string) (io.ReadCloser, error) {
	named, err := docker.ParseDockerRef(ref)
	if err != nil {
		return nil, errors.Wrapf(err, "failed parse docker ref %s", ref)
	}
	host := docker.Domain(named)
	sref := fmt.Sprintf("%s/%s", host, docker.Path(named))
	nref, err := name.ParseReference(sref)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse ref %q (%q)", sref, digest)
	}
	keychain := auth.GetRegistryKeyChain(host, labels)

	var tr http.RoundTripper
	tr, err = registry.AuthnTransport(nref, r.transport, keychain)
	if err != nil {
		return nil, errors.Wrapf(err, "failt to create authn transport %v", keychain)
	}
	url := fmt.Sprintf("%s://%s/v2/%s/blobs/%s",
		nref.Context().Registry.Scheme(),
		nref.Context().RegistryStr(),
		nref.Context().RepositoryStr(),
		digest)

	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "faild to new http get %s", url)
	}

	client := newRetryHTTPClient(tr)
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "faild to http get %s", url)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to GET request with code %d", res.StatusCode)
	}
	return res.Body, nil
}

func newRetryHTTPClient(tr http.RoundTripper) *retryablehttp.Client {
	retryClient := retryablehttp.NewClient()
	retryClient.HTTPClient.Transport = tr
	retryClient.HTTPClient.Timeout = HTTPClientTimeOut
	retryClient.Logger = nil
	return retryClient
}
