package main

import (
    "../simpleaes"
    "fmt"
)


func main() {
    key := "bardzotrudnykluczszyfrujący"
    aes, err := simpleaes.New(16, key)
    if err != nil {
        panic(err)
    }
    phrase := "czy nie mają koty na nietoperze ochoty?"
    buf := aes.Encrypt([]byte(phrase))
    fmt.Println(buf)
    buf = aes.Decrypt(buf)
    fmt.Println(string(buf))
}
