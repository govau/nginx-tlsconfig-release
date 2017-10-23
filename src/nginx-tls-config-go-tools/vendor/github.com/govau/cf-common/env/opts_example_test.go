package env_test

import (
	"fmt"
	"os"

	"github.com/govau/cf-common/env"
)

func ExampleWithOSLookup() {
	os.Setenv("FOO", "bar") // Simulate OS env.

	vs := env.NewVarSet(env.WithOSLookup())

	v := vs.MustString("FOO")

	fmt.Println(v)
}

func ExampleWithMapLookup() {
	m := map[string]string{
		"FOO": "bar",
	}

	vs := env.NewVarSet(env.WithMapLookup(m))

	v := vs.MustString("FOO")

	fmt.Println(v)
}
