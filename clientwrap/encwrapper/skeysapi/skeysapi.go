// Package for secure etcd
package skeysapi

import (
	"encoding/base64"
	etcd "github.com/coreos/etcd/client"
	"github.com/coreos/etcd/clientwrap/encwrapper/encconfig"
	"golang.org/x/net/context"
)

type ValueGetWrapFunc func(m string) (string, error)
type ValueSetUnwrapFunc func(m string) (string, error)

// secureKeysAPI internal structure
type secureKeysAPI struct {
	k              etcd.KeysAPI
	valueSetWrap   ValueGetWrapFunc
	valueGetUnwrap ValueSetUnwrapFunc
}

// Create a secure wrapper around the KeysAPI to perform additional
// encryption/signing, etc. If a field besides KeysAPI is empty, it is
// considered that the feature is disabled.
func NewSecureKeysAPI(k etcd.KeysAPI, encConf encconfig.EncConfig) (etcd.KeysAPI, error) {

	// If no encryption configuration, set to just return keysAPI
	// This should be updated when the option of choosing between subsets of
	// Encryption/Signing/etc. is available
	if encConf == nil {
		return k, nil
	}

    wrapper, unwrapper := GetWrappers(encConf) 

	skapi := secureKeysAPI{
		k:              k,
		valueSetWrap:   wrapper,
		valueGetUnwrap: unwrapper,
	}
	return &skapi, nil
}

func GetWrappers (encConf encconfig.EncConfig) (ValueGetWrapFunc, ValueSetUnwrapFunc) {
    wrapper := func(m string) (string, error) {
		plainBytes := []byte(m)
		encBytes, wrapErr := encConf.Encrypt(plainBytes)
		if wrapErr != nil {
			return "", wrapErr
		}

		bytesStored := encBytes
		encoded := base64.StdEncoding.EncodeToString(bytesStored)
		return encoded, nil
	}

	// Perform opposite operations of wrapper for value
	unwrapper := func(m string) (string, error) {
		bytesStored, unwrapErr := base64.StdEncoding.DecodeString(m)
		if unwrapErr != nil {
			return "", unwrapErr
		}

		encBytes := bytesStored
		plainBytes, unwrapErr := encConf.Decrypt(encBytes)
		if unwrapErr != nil {
			return "", unwrapErr
		}

		return string(plainBytes), nil
	}

    return wrapper, unwrapper
}



/*** Implement the KeysAPI Interface ***/

// Get retrieves a set of Nodes from etcd
func (s *secureKeysAPI) Get(ctx context.Context, key string, opts *etcd.GetOptions) (*etcd.Response, error) {
	r, err := s.k.Get(ctx, key, opts)
	if err != nil {
		return nil, err
	}

	err = s.unwrapResponse(r)
	if err != nil {
		return r, err
	}

	return r, err
}

// Set assigns a new value to a Node identified by a given key. The caller
// may define a set of conditions in the SetOptions. If SetOptions.Dir=true
// then value is ignored.
func (s *secureKeysAPI) Set(ctx context.Context, key, value string, opts *etcd.SetOptions) (*etcd.Response, error) {
	var err error
	if s.valueSetWrap != nil {
		value, err = s.valueSetWrap(value)
		if err != nil {
			return nil, err
		}
	}

	r, err := s.k.Set(ctx, key, value, opts)
	if err != nil {
		return nil, err
	}

	err = s.unwrapResponse(r)
	if err != nil {
		return r, err
	}

	return r, err

}

// Delete removes a Node identified by the given key, optionally destroying
// all of its children as well. The caller may define a set of required
// conditions in an DeleteOptions object.
func (s *secureKeysAPI) Delete(ctx context.Context, key string, opts *etcd.DeleteOptions) (*etcd.Response, error) {
	r, err := s.k.Delete(ctx, key, opts)
	if err != nil {
		return nil, err
	}

	err = s.unwrapResponse(r)
	if err != nil {
		return r, err
	}

	return r, err

}

// Create is an alias for Set w/ PrevExist=false
func (s *secureKeysAPI) Create(ctx context.Context, key, value string) (*etcd.Response, error) {
	var err error
	if s.valueSetWrap != nil {
		value, err = s.valueSetWrap(value)
		if err != nil {
			return nil, err
		}
	}

	r, err := s.k.Create(ctx, key, value)
	if err != nil {
		return nil, err
	}

	err = s.unwrapResponse(r)
	if err != nil {
		return r, err
	}

	return r, err
}

// CreateInOrder is used to atomically create in-order keys within the given directory.
func (s *secureKeysAPI) CreateInOrder(ctx context.Context, dir, value string, opts *etcd.CreateInOrderOptions) (*etcd.Response, error) {
	var err error
	if s.valueSetWrap != nil {
		value, err = s.valueSetWrap(value)
		if err != nil {
			return nil, err
		}
	}

	r, err := s.k.CreateInOrder(ctx, dir, value, opts)
	if err != nil {
		return nil, err
	}

	err = s.unwrapResponse(r)
	if err != nil {
		return r, err
	}

	return r, err
}

// Update is an alias for Set w/ PrevExist=true
func (s *secureKeysAPI) Update(ctx context.Context, key, value string) (*etcd.Response, error) {
	var err error
	if s.valueSetWrap != nil {
		value, err = s.valueSetWrap(value)
		if err != nil {
			return nil, err
		}
	}

	r, err := s.k.Update(ctx, key, value)
	if err != nil {
		return nil, err
	}

	err = s.unwrapResponse(r)
	if err != nil {
		return r, err
	}

	return r, err
}

// Watcher builds a new Watcher targeted at a specific Node identified
// by the given key. The Watcher may be configured at creation time
// through a WatcherOptions object. The returned Watcher is designed
// to emit events that happen to a Node, and optionally to its children.
func (s *secureKeysAPI) Watcher(key string, opts *etcd.WatcherOptions) etcd.Watcher {
	return s.k.Watcher(key, opts)
}

// Helper function to unwrap the response
func (s *secureKeysAPI) unwrapResponse(r *etcd.Response) error {
	if s.valueGetUnwrap != nil {

		// Unwrap return node and previous node
		err := s.unwrapNode(r.Node)
		if err != nil {
			return err
		}

		err = s.unwrapNode(r.PrevNode)
		if err != nil {
			return err
		}
	}

	return nil

}

// Helper function to run Get Unwrap function on all nodes in the node tree
func (s *secureKeysAPI) unwrapNode(n *etcd.Node) error {
	if n == nil {
		return nil
	}

	// Unwrap all children nodes
	for _, nc := range n.Nodes {
		err := s.unwrapNode(nc)
		if err != nil {
			return err
		}
	}

	// Unwrap current node
	if n.Value != "" {
		val, err := s.valueGetUnwrap(n.Value)
		if err != nil {
			return err
		}
		n.Value = val
	}

	return nil
}
