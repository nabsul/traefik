package azure

import (
	"encoding/json"
	"fmt"
	"github.com/containous/traefik/v2/pkg/cli"
	"github.com/containous/traefik/v2/pkg/config/static"
)

func NewCmd(traefikConfiguration *static.Configuration, loaders []cli.ResourceLoader) *cli.Command {
	return &cli.Command{
		Name:          "azure",
		Description:   "Runs azure related cert storage commands",
		Configuration: traefikConfiguration,
		Resources:     loaders,
		Run:           func(args []string) error { return run(traefikConfiguration, loaders, args) },
		Hidden:        false,
		AllowArg:      true,
	}
}

func run(traefikConfiguration *static.Configuration, loaders []cli.ResourceLoader, strings []string) error {
	fmt.Println("traefikConfiguration")
	err := printJson(traefikConfiguration)
	if err != nil {return err}
	fmt.Println("loaders")
	err = printJson(loaders)
	if err != nil {return err}
	fmt.Println("strings")
	err = printJson(strings)
	if err != nil {return err}
	fmt.Println(traefikConfiguration.CertificatesResolvers["default"].ACME.AzureKey)
	fmt.Println(traefikConfiguration.CertificatesResolvers["default"].ACME.AzureKey == "")

	for k, v := range traefikConfiguration.CertificatesResolvers {
		fmt.Printf("Found: %s\n", k)
		printJson(v)
	}

	return nil
}

func printJson(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	fmt.Printf("params: %s\n", string(data))
	return nil
}
