// Copyright 2009 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/blasten/rsync"
)

func main() {
	rsync.Push(nil, "src")
	rsync.Pull(nil, "src")
	fmt.Println("Run")
}
