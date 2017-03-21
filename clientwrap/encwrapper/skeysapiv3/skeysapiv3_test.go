// Package for secure etcd
package skeysapiv3

import (
	"github.com/coreos/etcd/clientwrap/encwrapper/encconfig"
	"testing"

	"math/rand"
	"strconv"

	"golang.org/x/net/context"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/integration"
	"github.com/coreos/etcd/pkg/testutil"
)

// Test simple get/set with skeysapi
func TestSimpleGetSet(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get
	kapi := clientv3.NewKV(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	_, err = skapi.Put(context.TODO(), "/foo", "bar")
	if err != nil {
		t.Fatal(err)
	}

	r, err := skapi.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar" {
		t.Fatalf("Expected %v, Got %v", "bar", r.Kvs[0].Value)
	}

	_, err = skapi.Put(context.TODO(), "/foo", "bar2")
	if err != nil {
		t.Fatal(err)
	}

	r, err = skapi.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar2" {
		t.Fatalf("Expected %v, Got %v", "bar2", r.Kvs[0].Value)
	}

}

// Test Delete
func TestDelete(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get
	kapi := clientv3.NewKV(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	_, err = skapi.Put(context.TODO(), "/foo", "bar")
	if err != nil {
		t.Fatal(err)
	}

	_, err = skapi.Delete(context.TODO(), "/foo")
	if err != nil {
		t.Fatal("Delete failed")
	}

	r, err := skapi.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 0 {
		t.Fatal("Received unexpected number of results")
	}

}

func TestDoDelete(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get
	kapi := clientv3.NewKV(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	_, err = skapi.Put(context.TODO(), "/foo", "bar")
	if err != nil {
		t.Fatal(err)
	}

	_, err = skapi.Do(context.TODO(), skapi.OpDelete("/foo"))
	if err != nil {
		t.Fatal("Delete failed")
	}

	r, err := skapi.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 0 {
		t.Fatal("Received unexpected number of results")
	}

}

func TestDoPut(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get
	kapi := clientv3.NewKV(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	opPut, err := skapi.OpPut("/foo", "bar")
	if err != nil {
		t.Fatal("Failed to create Op")
	}

	_, err = skapi.Do(context.TODO(), opPut)
	if err != nil {
		t.Fatal(err)
	}

	r, err := skapi.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar" {
		t.Fatalf("Expected %v, Got %v", "bar", r.Kvs[0].Value)
	}
}

func TestDoGet(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get
	kapi := clientv3.NewKV(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	_, err = skapi.Put(context.TODO(), "/foo", "bar")
	if err != nil {
		t.Fatal(err)
	}

	res, err := skapi.Do(context.TODO(), skapi.OpGet("/foo"))

	r := res.Get()

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar" {
		t.Fatalf("Expected %v, Got %v", "bar", r.Kvs[0].Value)
	}
}

// Test simple get/set with client wrap
func TestClientSimpleGetSet(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = SecureClient(cli, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cli.Put(context.TODO(), "/foo", "bar")
	if err != nil {
		t.Fatal(err)
	}

	r, err := cli.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar" {
		t.Fatalf("Expected %v, Got %v", "bar", r.Kvs[0].Value)
	}

	_, err = cli.Put(context.TODO(), "/foo", "bar2")
	if err != nil {
		t.Fatal(err)
	}

	r, err = cli.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar2" {
		t.Fatalf("Expected %v, Got %v", "bar2", r.Kvs[0].Value)
	}

}

func runTestsonTwoSkapis(t *testing.T, skapi1, skapi2 clientv3.KV) {
	_, err := skapi1.Put(context.TODO(), "/foo", "bar")
	if err != nil {
		t.Fatal(err)
	}

	r, err := skapi1.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar" {
		t.Fatalf("Expected %v, Got %v", "bar", r.Kvs[0].Value)
	}

	r, err = skapi2.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar" {
		t.Fatalf("Expected %v, Got %v", "bar", r.Kvs[0].Value)
	}

	_, err = skapi2.Put(context.TODO(), "/foo", "bar2")
	if err != nil {
		t.Fatal(err)
	}

	r, err = skapi1.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar2" {
		t.Fatalf("Expected %v, Got %v", "bar2", r.Kvs[0].Value)
	}

	r, err = skapi2.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar2" {
		t.Fatalf("Expected %v, Got %v", "bar2", r.Kvs[0].Value)
	}
}

// Test using multiple sKeysApis with same KeysApi and the same EncConfig
func TestMultipleSameKeysApisOneEncConf(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get
	kapi := clientv3.NewKV(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi1, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	skapi2, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	runTestsonTwoSkapis(t, skapi1, skapi2)
}

// Test using multiple sKeysApis with diff KeysApi and the same EncConfig
func TestMultipleDiffKeysApisOneEncConf(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get
	kapi1 := clientv3.NewKV(cli)
	kapi2 := clientv3.NewKV(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi1, err := NewSecureKeysAPI(kapi1, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	skapi2, err := NewSecureKeysAPI(kapi2, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	runTestsonTwoSkapis(t, skapi1, skapi2)
}

// Test if same key sKeysApis can decrypt each other
func TestSameKeyEncryptDecryptAcrossDifferentSkeysApis(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get
	kapi1 := clientv3.NewKV(cli)
	kapi2 := clientv3.NewKV(cli)

	encConfig1, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	encConfig2, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi1, err := NewSecureKeysAPI(kapi1, encConfig1)
	if err != nil {
		t.Fatal(err)
	}

	skapi2, err := NewSecureKeysAPI(kapi2, encConfig2)
	if err != nil {
		t.Fatal(err)
	}

	runTestsonTwoSkapis(t, skapi1, skapi2)
}

// Test if different keys sKeysAPIs cannot decrypt each other
func TestDiffKeyEncryptDecryptAcrossDifferentSkeysApis(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get
	kapi1 := clientv3.NewKV(cli)
	kapi2 := clientv3.NewKV(cli)

	encConfig1, err := encconfig.NewAESCBCEncConfig([]byte("this is the key1"))
	if err != nil {
		t.Fatal(err)
	}

	encConfig2, err := encconfig.NewAESCBCEncConfig([]byte("this is the key2"))
	if err != nil {
		t.Fatal(err)
	}

	skapi1, err := NewSecureKeysAPI(kapi1, encConfig1)
	if err != nil {
		t.Fatal(err)
	}

	skapi2, err := NewSecureKeysAPI(kapi2, encConfig2)
	if err != nil {
		t.Fatal(err)
	}

	_, err = skapi1.Put(context.TODO(), "/foo", "bar")
	if err != nil {
		t.Fatal(err)
	}

	r, err := skapi2.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) == "bar" {
		t.Fatal("Cross key decryption is possible")
	}
}

// Test concurrent sKeysAPIs with shared KeysApis and same EncConfig
func TestConcurrency(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get
	kapi := clientv3.NewKV(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan bool)

	iterations := 100
	enc_test := func(key string) {
		for i := 0; i < iterations; i++ {
			p := make([]byte, 128)
			_, err := rand.Read(p)
			if err != nil {
				done <- false
				return
			}

			pstring := string(p)

			// Check if Put/Get works with secure Keys API
			if _, err = skapi.Put(context.Background(), key, pstring); err != nil {
				t.Error(err)
				done <- false
				return
			}

			r, err := skapi.Get(context.Background(), key)

			if err != nil {
				t.Error(err)
				done <- false
				return
			}

			if len(r.Kvs) != 1 {
				t.Fatal("Received unexpected number of results")
				done <- false
				return
			}

			if string(r.Kvs[0].Value) != pstring {
				t.Errorf("Expected %v, Got %v", pstring, r.Kvs[0].Value)
				done <- false
				return
			}
		}
		done <- true
	}

	routines := 100
	for i := 0; i < routines; i++ {
		go enc_test("key" + strconv.Itoa(i))
	}

	for i := 0; i < routines; i++ {
		if b := <-done; !b {
			t.Error("Concurrency broken")
		}
	}

}

// Test if encryption is done using the api
func TestEncryption(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get
	kapi := clientv3.NewKV(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	_, err = skapi.Put(context.TODO(), "foo", "bar")
	if err != nil {
		t.Fatal(err)
	}

	r, err := skapi.Get(context.TODO(), "foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar" {
		t.Fatalf("Expected %v, Got %v", "bar", r.Kvs[0].Value)
	}

	// Test if stored encrypted
	kapi = clientv3.NewKV(cli)

	r, err = kapi.Get(context.TODO(), "foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) == "bar" {
		t.Fatalf("Data was not encrypted")
	}

}

// Test simple get/set with client wrap actually does encryption
func TestClientEncryption(t *testing.T) {
	defer testutil.AfterTest(t)

	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 3})
	defer clus.Terminate(t)

	cli := clus.RandClient()

	// Test encryption Put/Get

	kapi := clientv3.NewKV(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = SecureClient(cli, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cli.Put(context.TODO(), "/foo", "bar")
	if err != nil {
		t.Fatal(err)
	}

	r, err := cli.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) != "bar" {
		t.Fatalf("Expected %v, Got %v", "bar", r.Kvs[0].Value)
	}

	r, err = kapi.Get(context.TODO(), "/foo")

	if len(r.Kvs) != 1 {
		t.Fatal("Received unexpected number of results")
	}

	if string(r.Kvs[0].Value) == "bar" {
		t.Fatal("Encryption was not performed")
	}

}
