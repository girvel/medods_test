package main

import (
	medods_test "github.com/girvel/medods_test/src"  // TODO rename project
)

func main() {
    db, err := medods_test.NewPgx()
    if err != nil {
        panic(err.Error())  // TODO log
    }
    defer db.Close()

    api := medods_test.NewAPI(db)
    api.Run()
}
