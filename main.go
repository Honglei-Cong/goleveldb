
package main

import (
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"fmt"
	"bytes"
)

func main() {

	stor := storage.NewMemStorage()
	db, err := leveldb.Open(stor, nil)
	if err != nil {
		fmt.Errorf("open db failed: %s", err)
		return
	}
	defer db.Close()

	testKey := []byte("testKey")
	testValue := []byte("testValue")
	if err := db.Put(testKey, testValue, nil); err != nil {
		fmt.Printf("put key failed: %s", err)
		return
	}

	if v, err := db.Get(testKey, nil); err != nil {
		fmt.Printf("get key failed: %s", err)
		return
	} else if bytes.Compare(v, testValue) != 0 {
		fmt.Printf("compare value failed: %s vs %s", v, testValue)
		return
	}

	fmt.Println("done")
}