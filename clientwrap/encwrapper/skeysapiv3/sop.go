// This file will contain secure Op operators
package skeysapiv3

import (
	//pb "github.com/coreos/etcd/etcdserver/etcdserverpb"
	etcd "github.com/coreos/etcd/clientv3"
)

func (s *secureKV) OpGet(key string, opts ...etcd.OpOption) etcd.Op {
	return etcd.OpGet(key, opts...)
}

func (s *secureKV) OpDelete(key string, opts ...etcd.OpOption) etcd.Op {
	return etcd.OpDelete(key, opts...)
}

func (s *secureKV) OpPut(key, val string, opts ...etcd.OpOption) (etcd.Op, error) {
	var err error
	if s.valueSetWrap != nil {
		val, err = s.valueSetWrap(val)
		if err != nil {
			return etcd.Op{}, err
		}
	}

	return etcd.OpPut(key, val, opts...), nil
}

func (s *secureKV) OpValue(val string) (string, error) {
	var err error
	if s.valueSetWrap != nil {
		val, err = s.valueSetWrap(val)
		if err != nil {
			return "", err
		}
	}

	return val, nil
}
