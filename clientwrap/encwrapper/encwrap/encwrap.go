package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/coreos/etcd/clientwrap/encwrapper/encconfig"
	"github.com/coreos/etcd/clientwrap/encwrapper/skeysapiv3"
)

func main() {
	key_file_ptr := flag.String("key", "", "path to key file")
	in_file_ptr := flag.String("in", "", "path to input file")
	out_file_ptr := flag.String("out", "", "path of output file (Optional)")
	enc_ptr := flag.Bool("encrypt", false, "perform encryption")
	dec_ptr := flag.Bool("decrypt", false, "perform decryption")

	flag.Parse()

	if *enc_ptr == *dec_ptr {
		fmt.Println("Please specify Encrypt/Decrypt")
		os.Exit(-1)
	}

	enc_flag := *enc_ptr

	if *in_file_ptr == "" {
		fmt.Println("Please specify in file")
		os.Exit(-1)
	}

	if *key_file_ptr == "" {
		fmt.Println("Please specify key file")
		os.Exit(-1)
	}

	out_file := *out_file_ptr

	in_file := *in_file_ptr
	key_file := *key_file_ptr

	key, err := ioutil.ReadFile(key_file)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)

	}

	plain, err := ioutil.ReadFile(in_file)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	encConfig, err := encconfig.NewAESCBCEncConfig(key)
	if err != nil {
		log.Fatal(err)
	}

	wrapper, unwrapper := skeysapiv3.GetWrappers(encConfig)

	var s string
	if enc_flag {
		s, err = wrapper(string(plain))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		s, err = unwrapper(string(plain))
		if err != nil {
			log.Fatal(err)
		}
	}
	output(out_file, s)

	return
}

func output(outfile, result string) {
	if outfile == "" {
		fmt.Printf(result)
	} else {
		err := ioutil.WriteFile(outfile, []byte(result), 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
}
