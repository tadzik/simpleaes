package main

import (
    "github.com/tadzik/simpleaes"
    "fmt"
    "flag"
    "os"
)

var decrypt = flag.Bool("d", false, "decrypt")

func main() {
    flag.Parse()
    if len(flag.Args()) != 2 {
        fmt.Println("Usage: encryptfile <src> <dest>")
        return
    }
    key := "bardzotrudnykluczszyfrujący"
    fileSrc, err := os.Open(flag.Arg(0))
    if err != nil {
        panic(err)
    }
    defer fileSrc.Close()
    fileDst, err := os.Create(flag.Arg(1))
    if err != nil {
        panic(err)
    }
    defer fileDst.Close()
    aes, err := simpleaes.New(16, key)
    if err != nil {
        panic(err)
    }
    if *decrypt {
        err = aes.DecryptStream(fileSrc, fileDst)
    } else {
        err = aes.EncryptStream(fileSrc, fileDst)
    }
    if err != nil {
        panic(err)
    }
}
