// Package for secure etcd
package skeysapi

import (
	"math/rand"
	"strconv"

	"github.com/coreos/etcd/clientwrap/encwrapper/encconfig"
	"testing"

	"golang.org/x/net/context"

	"github.com/coreos/etcd/client"
	"github.com/coreos/etcd/integration"
	"github.com/coreos/etcd/pkg/testutil"
)

// Test simple get/set with skeysapi
func TestSimpleGetSet(t *testing.T) {
	defer testutil.AfterTest(t)
	cl := integration.NewCluster(t, 1)
	cl.Launch(t)
	defer cl.Terminate(t)

	// test connection refused; expect no error failover
	cli := integration.MustNewHTTPClient(t, []string{cl.URL(0), cl.URL(0)}, nil)

	kapi := client.NewKeysAPI(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	// Check if Set/Get works with secure Keys API
	if _, err = skapi.Set(context.Background(), "/foo", "bar", nil); err != nil {
		t.Fatal(err)
	}

	resp, err := skapi.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value != "bar" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar", resp.Node.Value)
	}

	// Check if Set/Get works with secure Keys API
	if _, err = skapi.Set(context.Background(), "/foo", "bar2", nil); err != nil {
		t.Fatal(err)
	}

	resp, err = skapi.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value != "bar2" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar2", resp.Node.Value)
	}

}

// Test Delete
func TestDelete(t *testing.T) {
	defer testutil.AfterTest(t)
	cl := integration.NewCluster(t, 1)
	cl.Launch(t)
	defer cl.Terminate(t)

	// test connection refused; expect no error failover
	cli := integration.MustNewHTTPClient(t, []string{cl.URL(0), cl.URL(0)}, nil)

	kapi := client.NewKeysAPI(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	// Check if Set/Get works with secure Keys API
	if _, err = skapi.Set(context.Background(), "/foo", "bar", nil); err != nil {
		t.Fatal(err)
	}

	_, err = skapi.Delete(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	_, err = skapi.Get(context.Background(), "/foo", nil)

	if err == nil {
		t.Fatalf("Should have no entry for key")
	}
}

// Test Create
func TestCreate(t *testing.T) {
	defer testutil.AfterTest(t)
	cl := integration.NewCluster(t, 1)
	cl.Launch(t)
	defer cl.Terminate(t)

	// test connection refused; expect no error failover
	cli := integration.MustNewHTTPClient(t, []string{cl.URL(0), cl.URL(0)}, nil)

	kapi := client.NewKeysAPI(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	// Check if Set/Get works with secure Keys API
	if _, err = skapi.Set(context.Background(), "/foo", "bar", nil); err != nil {
		t.Fatal(err)
	}

	resp, err := skapi.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value != "bar" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar", resp.Node.Value)
	}
}

// Test CreateInOrder
func TestCreateInOrder(t *testing.T) {
	defer testutil.AfterTest(t)
	cl := integration.NewCluster(t, 1)
	cl.Launch(t)
	defer cl.Terminate(t)

	// test connection refused; expect no error failover
	cli := integration.MustNewHTTPClient(t, []string{cl.URL(0), cl.URL(0)}, nil)

	kapi := client.NewKeysAPI(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	// Check if Set/Get works with secure Keys API
	if _, err = skapi.CreateInOrder(context.Background(), "/foo", "bar", nil); err != nil {
		t.Fatal(err)
	}

	resp, err := skapi.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Nodes[0].Value != "bar" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar", resp.Node.Value)
	}
}

// Test Update
func TestUpdate(t *testing.T) {
	defer testutil.AfterTest(t)
	cl := integration.NewCluster(t, 1)
	cl.Launch(t)
	defer cl.Terminate(t)

	// test connection refused; expect no error failover
	cli := integration.MustNewHTTPClient(t, []string{cl.URL(0), cl.URL(0)}, nil)

	kapi := client.NewKeysAPI(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	// Check if Set/Get works with secure Keys API
	if _, err = skapi.Create(context.Background(), "/foo", "bar"); err != nil {
		t.Fatal(err)
	}

	resp, err := skapi.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value != "bar" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar", resp.Node.Value)
	}

	// Check if Set/Get works with secure Keys API
	if _, err = skapi.Update(context.Background(), "/foo", "bar2"); err != nil {
		t.Fatal(err)
	}

	resp, err = skapi.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value != "bar2" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar2", resp.Node.Value)
	}
}

func runTestsOnTwoSkapis(t *testing.T, skapi1, skapi2 client.KeysAPI) {
	// Check if Set/Get works with secure Keys API
	if _, err := skapi1.Set(context.Background(), "/foo", "bar", nil); err != nil {
		t.Fatal(err)
	}

	resp, err := skapi1.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value != "bar" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar", resp.Node.Value)
	}

	resp, err = skapi2.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value != "bar" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar", resp.Node.Value)
	}

	// Check if Set/Get works with secure Keys API
	if _, err = skapi2.Set(context.Background(), "/foo", "bar2", nil); err != nil {
		t.Fatal(err)
	}

	resp, err = skapi1.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value != "bar2" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar2", resp.Node.Value)
	}

	resp, err = skapi2.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value != "bar2" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar2", resp.Node.Value)
	}
}

// Test using multiple sKeysApis with same KeysApi and the same EncConfig
func TestMultipleSameKeysApisOneEncConf(t *testing.T) {
	defer testutil.AfterTest(t)
	cl := integration.NewCluster(t, 1)
	cl.Launch(t)
	defer cl.Terminate(t)

	// test connection refused; expect no error failover
	cli := integration.MustNewHTTPClient(t, []string{integration.UrlScheme, cl.URL(0)}, nil)

	kapi := client.NewKeysAPI(cli)

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

	runTestsOnTwoSkapis(t, skapi1, skapi2)
}

// Test using multiple sKeysApis with diff KeysApi and the same EncConfig
func TestMultipleDiffKeysApisOneEncConf(t *testing.T) {
	defer testutil.AfterTest(t)
	cl := integration.NewCluster(t, 1)
	cl.Launch(t)
	defer cl.Terminate(t)

	// test connection refused; expect no error failover
	cli := integration.MustNewHTTPClient(t, []string{cl.URL(0), cl.URL(0)}, nil)

	kapi1 := client.NewKeysAPI(cli)
	kapi2 := client.NewKeysAPI(cli)

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

	runTestsOnTwoSkapis(t, skapi1, skapi2)
}

// Test if same key sKeysApis can decrypt each other
func TestSameKeyEncryptDecryptAcrossDifferentSkeysApis(t *testing.T) {
	defer testutil.AfterTest(t)
	cl := integration.NewCluster(t, 1)
	cl.Launch(t)
	defer cl.Terminate(t)

	// test connection refused; expect no error failover
	cli := integration.MustNewHTTPClient(t, []string{cl.URL(0), cl.URL(0)}, nil)

	kapi1 := client.NewKeysAPI(cli)
	kapi2 := client.NewKeysAPI(cli)

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

	runTestsOnTwoSkapis(t, skapi1, skapi2)
}

// Test if different key sKeysAPIs cannot decrypt each other
func TestDiffKeyEncryptDecryptAcrossDifferentSkeysApis(t *testing.T) {
	defer testutil.AfterTest(t)
	cl := integration.NewCluster(t, 1)
	cl.Launch(t)
	defer cl.Terminate(t)

	// test connection refused; expect no error failover
	cli := integration.MustNewHTTPClient(t, []string{cl.URL(0), cl.URL(0)}, nil)

	kapi1 := client.NewKeysAPI(cli)
	kapi2 := client.NewKeysAPI(cli)

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

	// Check if Set/Get works with secure Keys API
	if _, err := skapi1.Set(context.Background(), "/foo", "bar", nil); err != nil {
		t.Fatal(err)
	}

	resp, err := skapi1.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value != "bar" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar", resp.Node.Value)
	}

	resp, err = skapi2.Get(context.Background(), "/foo", nil)

	if err == nil && resp.Node.Value == "bar" {
		t.Fatal("Different encconfig key could decrypt")
	}
}

// Test concurrent sKeysAPIs with shared KeysApis and same EncConfig
func TestConcurrency(t *testing.T) {
	defer testutil.AfterTest(t)
	cl := integration.NewCluster(t, 1)
	cl.Launch(t)
	defer cl.Terminate(t)

	// test connection refused; expect no error failover
	cli := integration.MustNewHTTPClient(t, []string{cl.URL(0), cl.URL(0)}, nil)

	kapi := client.NewKeysAPI(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan bool)

	iterations := 1000
	enc_test := func(key string) {
		for i := 0; i < iterations; i++ {
			p := make([]byte, 128)
			_, err := rand.Read(p)
			if err != nil {
				done <- false
				return
			}

			pstring := string(p)

			// Check if Set/Get works with secure Keys API
			if _, err = skapi.Set(context.Background(), key, pstring, nil); err != nil {
				t.Error(err)
				done <- false
				return
			}

			resp, err := skapi.Get(context.Background(), key, nil)

			if err != nil {
				t.Error(err)
				done <- false
				return
			}

			if resp.Node.Value != pstring {
				t.Error("Value did not match")
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
	cl := integration.NewCluster(t, 1)
	cl.Launch(t)
	defer cl.Terminate(t)

	// test connection refused; expect no error failover
	cli := integration.MustNewHTTPClient(t, []string{cl.URL(0), cl.URL(0)}, nil)

	kapi := client.NewKeysAPI(cli)

	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		t.Fatal(err)
	}

	skapi, err := NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		t.Fatal(err)
	}

	// Check if Set/Get works with secure Keys API
	if _, err = skapi.Set(context.Background(), "/foo", "bar", nil); err != nil {
		t.Fatal(err)
	}

	resp, err := skapi.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value != "bar" {
		t.Fatalf("Set value did not match, Expected %v, Got %v", "bar", resp.Node.Value)
	}

	// Check if the value is encrypted
	kapi = client.NewKeysAPI(cli)

	resp, err = kapi.Get(context.Background(), "/foo", nil)

	if err != nil {
		t.Fatal(err)
	}

	if resp.Node.Value == "bar" {
		t.Fatalf("Value is not encrypted in store")
	}
}
