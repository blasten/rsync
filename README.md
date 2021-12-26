# Go rsync

Minimal file syncing based on the rsync algorithm 
completely written in Go.

## Example

Push:
```go
func main() {
  conn, err := net.Dial("tcp", "<server>:1234")
  if err != nil {
    log.Fatalf("error creating connection:", err.Error())
  }
  defer conn.Close()
  for {
    // push the content of src every 5 seconds.
    rsync.Push(conn, "src")
    time.Sleep(time.Second * 5)
  }
}
```

Pull:
```go
func main() {
  listener, err := net.Listen("tcp", ":1234")
  if err != nil {
    log.Fatalf("error listening:", err.Error())
  }
  defer listener.Close()

  for {
    conn, err := listener.Accept()
    if err != nil {
      log.Println("error accepting connection:", err.Error())
      continue
    }
    // pull the content and copy it in src.
    rsync.Pull(conn, "src")
    conn.Close()
  }
}
```
