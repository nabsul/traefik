package azure

import (
	"encoding/base64"
	"encoding/json"
	"github.com/containous/traefik/v2/pkg/provider/acme"
	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/registration"
)

type AccountEntity struct {
	PartitionKey, RowKey, ETag string
	Email                      string
	RegistrationJson           string
	PrivateKey                 string
	KeyType                    string
}

func (acct *AccountEntity) Convert() (*acme.Account, error) {
	key, err := base64.StdEncoding.DecodeString(acct.PrivateKey)
	if err != nil {
		return nil, err
	}

	reg := &registration.Resource{}
	err = json.Unmarshal([]byte(acct.RegistrationJson), reg)
	if err != nil {
		return nil, err
	}

	return &acme.Account{
		Email: acct.Email,
		Registration: reg,
		PrivateKey: key,
		KeyType: certcrypto.KeyType(acct.KeyType),
	}, nil
}

func NewAccount(acct *acme.Account) (*AccountEntity, error) {
	regBytes, err := json.Marshal(acct.Registration)
	if err != nil {
		return nil, err
	}
	regStr := string(regBytes)

	return &AccountEntity{
		Email:            acct.Email,
		RegistrationJson: regStr,
		PrivateKey:       base64.StdEncoding.EncodeToString(acct.PrivateKey),
		KeyType:          string(acct.KeyType),
	}, nil
}
