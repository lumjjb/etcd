package example

import (
	"time"
)

var (
	dialTimeout    = 5 * time.Second
	requestTimeout = 1 * time.Second
	//endpoints      = []string{"localhost:2379", "localhost:22379", "localhost:32379"}
	endpoints = []string{"localhost:2379"}
)
