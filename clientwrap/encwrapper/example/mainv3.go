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

func Examplev3() {
	var plog = capnslog.NewPackageLogger("github.com/coreos/etcd", "clientv3")
	clientv3.SetLogger(plog)

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: dialTimeout,
	})
	if err != nil {
		log.Fatal(err)
	}

	/*** Additional code starts here ***/
	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		log.Fatal(err)
	}

	skv, err := skeysapiv3.SecureClient(cli, encConfig)
	if err != nil {
		log.Fatal(err)
	}

	_ = skv

	/*** Additional code ends here ***/

	defer cli.Close() // make sure to close the client

	_, err = cli.Put(context.TODO(), "foo", "bar")
	if err != nil {
		log.Fatal(err)
	}

	r, err := cli.Get(context.TODO(), "foo")
	for _, kv := range r.Kvs {
		fmt.Println(kv)
	}
}
