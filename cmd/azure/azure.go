package azure

import (
	"encoding/json"
	"fmt"
	"github.com/containous/traefik/v2/pkg/cli"
	"github.com/containous/traefik/v2/pkg/config/static"
	"github.com/containous/traefik/v2/pkg/provider/acme"
	azure2 "github.com/containous/traefik/v2/pkg/provider/acme/azure"
)

func NewCopyCmd(traefikConfiguration *static.Configuration, loaders []cli.ResourceLoader) *cli.Command {
	return &cli.Command{
		Name:          "azure-copy",
		Description:   "Copy Certs from local storage to Azure storage",
		Configuration: traefikConfiguration,
		Resources:     loaders,
		Run:           func(args []string) error { return copyCerts(traefikConfiguration, loaders, args) },
		Hidden:        false,
		AllowArg:      true,
	}
}

func copyCerts(traefikConfiguration *static.Configuration, loaders []cli.ResourceLoader, args []string) error {
	for k, c := range traefikConfiguration.CertificatesResolvers {
		if c.ACME == nil {
			fmt.Printf("Resolver %s has no ACME config\n", k)
			continue
		}

		if c.ACME.Storage == "" || c.ACME.AzureKey == "" || c.ACME.AzureAccount == "" || c.ACME.AzureTable == "" {
			fmt.Printf("Resolver %s not configured for both local and azure storage\n", k)
			continue
		}

		fmt.Printf("Processing resolver %s\n", k)
		local := acme.NewLocalStore(c.ACME.Storage)
		azure := azure2.NewAzureStore(c.ACME.AzureAccount, c.ACME.AzureKey, c.ACME.AzureTable)

		certs, err := local.GetAllData()
		if err != nil {
			return err
		}
		for id, data := range certs {
			fmt.Printf("Saving account %s\n", id)
			err := azure.SaveAccount(id, data.Account)
			if err != nil {
				return err
			}

			err = azure.SaveCertificates(id, data.Certificates)
			if err != nil {
				return err
			}
		}
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
