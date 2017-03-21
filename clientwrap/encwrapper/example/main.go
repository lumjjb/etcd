package example

import (
	client "github.com/coreos/etcd/client"
    "github.com/coreos/etcd/clientwrap/encwrapper/encconfig"
	"github.com/coreos/etcd/clientwrap/encwrapper/skeysapi"
	"golang.org/x/net/context"
	"log"
)

func ExampleMain() {

	cfg := client.Config{Endpoints: []string{"http://localhost:2379"}}

	c, err := client.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	_ = c
	log.Println("Creating New KeysAPI")
	kapi := client.NewKeysAPI(c)

	/*** ADDITIONAL CODE STARTS HERE ***/
	log.Println("Securing KeysAPI")
	encConfig, err := encconfig.NewAESCBCEncConfig([]byte("this is the key!"))
	if err != nil {
		log.Fatal(err)
	}

	kapi, err = skeysapi.NewSecureKeysAPI(kapi, encConfig)
	if err != nil {
		log.Fatal(err)
	}

	/*** ADDITIONAL CODE ENDS HERE ***/

	log.Println("Initiating SET")
	resp, err := kapi.Set(context.Background(), "test", "bar", nil)
	log.Println("Done SET")
	if err != nil {
		if err == context.Canceled {
			// ctx is canceled by another routine
			log.Println("Hello")
		} else if err == context.DeadlineExceeded {
			// ctx is attached with a deadline and it exceeded
		} else if cerr, ok := err.(*client.ClusterError); ok {
			// process (cerr.Errors)
			_ = cerr
		} else {
			// bad cluster endpoints, which are not etcd servers
		}
	}
	log.Println(resp)

	resp, err = kapi.Get(context.Background(), "test", nil)

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%q\n", resp.Node.Value)
}
