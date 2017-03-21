package example

import (
	"fmt"
	"log"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/pkg/capnslog"
	"golang.org/x/net/context"

	"github.com/coreos/etcd/clientwrap/encwrapper/encconfig"
	"github.com/coreos/etcd/clientwrap/encwrapper/skeysapiv3"
)

func Examplev3Do() {
	var plog = capnslog.NewPackageLogger("github.com/coreos/etcd", "clientv3")
	clientv3.SetLogger(plog)

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: dialTimeout,
	})
	if err != nil {
		log.Fatal(err)
	}

	kv := clientv3.NewKV(cli)
	_ = kv
	/*** Additional code starts here ***/
	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		log.Fatal(err)
	}

	skv, err := skeysapiv3.NewSecureKeysAPI(kv, encConfig)
	if err != nil {
		log.Fatal(err)
	}

	/*** Additional code ends here ***/

	defer cli.Close() // make sure to close the client

	//_, err = kv.Put(context.TODO(), "foo", "bar")
	putOp, err := skv.OpPut("foo", "bar")
	if err != nil {
		log.Fatal(err)
	}
	_, err = skv.Do(context.TODO(), putOp)
	if err != nil {
		log.Fatal(err)
	}

	r, err := skv.Get(context.TODO(), "foo")
	for _, kp := range r.Kvs {
		fmt.Println(kp)
	}
}
