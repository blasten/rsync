// Copyright 2021 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Running the example:
//   Pull files: go run main.go pull --dir=<local-directory> --host=:1234
//   Push files: go run main.go push --dir=<local-directory> --host=:1234

package main

import (
	"flag"
	"log"
	"net"
	"os"

	"github.com/blasten/rsync"
)

func main() {
	subCmd := flag.NewFlagSet("subcommand", flag.ExitOnError)

	var host string
	subCmd.StringVar(&host, "host", ":1234", "Specify the hostname. e.g. --host=server.io:1234")

	var dir string
	subCmd.StringVar(&dir, "dir", "", "This is the directory to push files to or pull files from. e.g. --dir=~/somepath/")

	if len(os.Args) < 2 {
		panic("Use go run main.go push <flags> or go run main.go pull <flags>")
	}

	subCmd.Parse(os.Args[2:])

	if len(dir) == 0 {
		panic("Specify a directory using the --dir flag")
	}

	op := os.Args[1]
	switch op {
	case "push":
		conn, err := net.Dial("tcp", host)
		if err != nil {
			log.Fatalf("could not push: %s", err.Error())
		}
		defer conn.Close()

		err = rsync.Push(conn, dir)
		if err != nil {
			log.Fatalf("could not push: %s", err.Error())
		}
	case "pull":
		l, err := net.Listen("tcp", host)
		if err != nil {
			log.Fatalf("could not listen: %s", err.Error())
		}
		defer l.Close()

		for {
			conn, err := l.Accept()
			if err != nil {
				log.Fatalf("coult not accept connection: %s", err.Error())
			}
			err = rsync.Pull(conn, dir)
			if err != nil {
				log.Fatalf("could not pull: %s", err.Error())
			}
		}
	default:
		panic("use push or pull")
	}
}
