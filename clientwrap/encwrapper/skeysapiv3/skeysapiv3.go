// Package for secure etcd
package skeysapiv3

import (
	"encoding/base64"
	etcd "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientwrap/encwrapper/encconfig"
	mvccpb "github.com/coreos/etcd/mvcc/mvccpb"
	"golang.org/x/net/context"
)

type ValueGetWrapFunc func(m string) (string, error)
type ValueSetUnwrapFunc func(m string) (string, error)

// secureKV internal structure
type secureKV struct {
	k              etcd.KV
	valueSetWrap   ValueGetWrapFunc
	valueGetUnwrap ValueSetUnwrapFunc
}

type SecureKV interface {
	etcd.KV
	OpGet(key string, opts ...etcd.OpOption) etcd.Op
	OpDelete(key string, opts ...etcd.OpOption) etcd.Op
	OpPut(key, val string, opts ...etcd.OpOption) (etcd.Op, error)
	OpValue(val string) (string, error)
}

// Makes the client secure by wrapping the internal KV. And returns the SecureKV
// interface to create Ops for Do/Txn
func SecureClient(c *etcd.Client, encConf encconfig.EncConfig) (SecureKV, error) {
	sKV, err := NewSecureKeysAPI(c.KV, encConf)
	if err != nil {
		return nil, err
	}

	c.KV = sKV
	return sKV, nil
}

// Create a secure wrapper around the KeysAPI to perform additional
// encryption/signing, etc. If a field besides KeysAPI is empty, it is
// considered that the feature is disabled.
func NewSecureKeysAPI(k etcd.KV, encConf encconfig.EncConfig) (SecureKV, error) {
	// If no encryption configuration, set to just return keysAPI
	// This should be updated when the option of choosing between subsets of
	// Encryption/Signing/etc. is available
	if encConf == nil {
		identity := func(m string) (string, error) {
			return m, nil
		}

		skapi := secureKV{
			k:              k,
			valueSetWrap:   identity,
			valueGetUnwrap: identity,
		}
		return &skapi, nil
	}

	wrapper, unwrapper := GetWrappers(encConf)

	skapi := secureKV{
		k:              k,
		valueSetWrap:   wrapper,
		valueGetUnwrap: unwrapper,
	}
	return &skapi, nil
}

func GetWrappers(encConf encconfig.EncConfig) (ValueGetWrapFunc, ValueSetUnwrapFunc) {

	// Wrapper function will take the message, encrypt it then base64
	// encode it to ensure that there are no null bytes in the value to store
	// This wrapper will be used to extend for other functionality. i.e.
	// Adding signatures for value integrity.
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
func (s *secureKV) Get(ctx context.Context, key string, opts ...etcd.OpOption) (*etcd.GetResponse, error) {
	r, err := s.k.Get(ctx, key, opts...)
	if err != nil {
		return nil, err
	}

	for _, kv := range r.Kvs {
		err = s.unwrapKeyValue(kv)
		if err != nil {
			return r, err
		}
	}

	return r, err
}

// Set assigns a new value to a Node identified by a given key. The caller
// may define a set of conditions in the SetOptions. If SetOptions.Dir=true
// then value is ignored.
func (s *secureKV) Put(ctx context.Context, key, val string, opts ...etcd.OpOption) (*etcd.PutResponse, error) {

	var err error
	if s.valueSetWrap != nil {
		val, err = s.valueSetWrap(val)
		if err != nil {
			return nil, err
		}
	}

	res, err := s.k.Put(ctx, key, val, opts...)
	if err != nil {
		return nil, err
	}

	// Else rewrite response for key value if exists
	if res.PrevKv != nil {
		s.unwrapKeyValue(res.PrevKv)
	}

	return res, nil
}

// Delete removes a Node identified by the given key, optionally destroying
// all of its children as well. The caller may define a set of required
// conditions in an DeleteOptions object.
func (s *secureKV) Delete(ctx context.Context, key string, opts ...etcd.OpOption) (*etcd.DeleteResponse, error) {
	r, err := s.k.Delete(ctx, key, opts...)
	if err != nil {
		return nil, err
	}

	for _, kv := range r.PrevKvs {
		s.unwrapKeyValue(kv)
	}

	return r, nil
}

func (s *secureKV) Compact(ctx context.Context, rev int64, opts ...etcd.CompactOption) (*etcd.CompactResponse, error) {
	return s.k.Compact(ctx, rev, opts...)
}

// Secure Ops should be done in the creation of the Op
func (s *secureKV) Do(ctx context.Context, op etcd.Op) (etcd.OpResponse, error) {
	r, err := s.k.Do(ctx, op)

	// Unwrap output
	if putResponse := r.Put(); putResponse != nil {
		if putResponse.PrevKv != nil {
			s.unwrapKeyValue(putResponse.PrevKv)
		}
	}

	if getResponse := r.Get(); getResponse != nil {
		for _, kv := range getResponse.Kvs {
			err = s.unwrapKeyValue(kv)
			if err != nil {
				return r, err
			}
		}
	}

	if delResponse := r.Del(); delResponse != nil {
		for _, kv := range delResponse.PrevKvs {
			s.unwrapKeyValue(kv)
		}
	}

	return r, nil
}

// Note: A transaction should only contain Put/Delete to be reliable as Gets
// and comparisons server side breaks the client encryption paradigm.
// TODO: Have a flag to allow less secure encryption algorithms to use
// full Txn stack.
func (s *secureKV) Txn(ctx context.Context) etcd.Txn {
	return s.k.Txn(ctx)
}

func (s *secureKV) unwrapKeyValue(m *mvccpb.KeyValue) error {
	if m.Value != nil {
		valString := string(m.Value)
		val, err := s.valueGetUnwrap(valString)
		if err != nil {
			return err
		}

		m.Value = []byte(val)
	}
	return nil
}
