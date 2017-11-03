package env_test

import (
	"fmt"

	"github.com/cloudfoundry-community/go-cfenv"
	"github.com/govau/cf-common/env"
)

func ExampleWithUPSLookup() {
	app, err := cfenv.Current()
	if err != nil {
		// ...
	}

	opts := []env.VarSetOpt{
		env.WithOSLookup(), // Always look in the OS env first.
		env.WithUPSLookup(app, "service-1"),
	}

	vs := env.NewVarSet(opts...)

	v := vs.MustString("FOO")

	fmt.Println(v)
}
