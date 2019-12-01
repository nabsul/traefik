package azure

import (
	"encoding/base64"
	"encoding/json"
	"github.com/containous/traefik/v2/pkg/provider/acme"
	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/registration"
)

func (s *TableStore) GetAccount(resolverName string) (*acme.Account, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	acct, ok := s.accounts[resolverName]
	if !ok {
		return nil, nil
	}

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

func (s *TableStore) SaveAccount(resolverName string, acct *acme.Account) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	regBytes, err := json.Marshal(acct.Registration)
	if err != nil {
		return err
	}
	regStr := string(regBytes)

	entity := &AccountEntity{
		Email:            acct.Email,
		RegistrationJson: regStr,
		PrivateKey:       base64.StdEncoding.EncodeToString(acct.PrivateKey),
		KeyType:          string(acct.KeyType),
	}

	s.accounts[resolverName] = entity

	entity.PartitionKey = accountPartition
	entity.RowKey = resolverName
	data, err := json.Marshal(entity)
	if err != nil {
		return err
	}

	return s.client.SaveRow(entity.PartitionKey, entity.RowKey, data)
}
