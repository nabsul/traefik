package azure

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/provider/acme"
	"sync"
	"time"
)

const refreshTime = int64(time.Minute * 10)
const accountPartition = "accounts"
const certificatePartition = "certificates"
const httpChallengePartition = "http_challenge"
const httpsChallengePartition = "https_challenge"

type AzureStore struct {
	client      *Client
	account     string
	key         string
	table       string
	nextRefresh int64
	lock        sync.RWMutex
	accounts    map[string]*AccountEntity
	certs       map[string][]*CertificateEntity
}

func NewAzureStore(account, key, table string) *AzureStore {
	return &AzureStore{
		client:      NewClient(account, key, table),
		nextRefresh: 0,
		accounts:    make(map[string]*AccountEntity),
		certs:       make(map[string][]*CertificateEntity),
	}
}

func (s *AzureStore) GetAccount(resolverName string) (*acme.Account, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	account, ok := s.accounts[resolverName]
	if !ok {
		return nil, nil
	}

	return account.Convert()
}

func (s *AzureStore) SaveAccount(resolverName string, a *acme.Account) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	entity, err := NewAccount(a)
	if err != nil {
		return err
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

func (s *AzureStore) GetCertificates(resolverName string) ([]*acme.CertAndStore, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	certs, ok := s.certs[resolverName]
	if !ok {
		return nil, errors.New("Account not found for resolver: " + resolverName)
	}

	result := make([]*acme.CertAndStore, len(certs))
	for i, c := range certs {
		converted, err := c.Convert()
		if err != nil {
			return nil, err
		}
		result[i] = converted
	}

	return result, nil
}

func (s *AzureStore) SaveCertificates(resolverName string, certs []*acme.CertAndStore) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	certEntities := make([]*CertificateEntity, len(certs))
	for i, c := range certs {
		e, err := NewCert(c)
		if err != nil {
			return err
		}
		certEntities[i] = e
	}

	s.certs[resolverName] = certEntities

	pk := fmt.Sprintf("%s_%s", certificatePartition, resolverName)
	for i, e := range certEntities {
		data, err := json.Marshal(e)
		if err != nil {
			return err
		}

		err = s.client.SaveRow(pk, fmt.Sprintf("cert_%d", i), data)
		if err != nil {
			return err
		}
	}

	return nil
}

func getHttpChallengeRowId(token, domain string) string {
	return fmt.Sprintf("%s_%s", token, domain)
}

func (s *AzureStore) GetHTTPChallengeToken(token, domain string) ([]byte, error) {
	data, err := s.client.GetRow(httpChallengePartition, getHttpChallengeRowId(token, domain))
	if err != nil {
		return nil, err
	}

	entity := &ChallengeEntity{}
	err = json.Unmarshal(data, entity)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(entity.Data)
}

func (s *AzureStore) SetHTTPChallengeToken(token, domain string, keyAuth []byte) error {
	entity := &ChallengeEntity{
		PartitionKey: httpChallengePartition,
		RowKey:       getHttpChallengeRowId(token, domain),
		ETag:         "*",
		Data:         base64.StdEncoding.EncodeToString(keyAuth),
	}

	data, err := json.Marshal(entity)
	if err != nil {
		return err
	}

	return s.client.SaveRow(httpChallengePartition, getHttpChallengeRowId(token, domain), data)
}

func (s *AzureStore) RemoveHTTPChallengeToken(token, domain string) error {
	rowId := fmt.Sprintf("%s_%s", token, domain)
	return s.client.DeleteRow(httpChallengePartition, rowId)
}

func (s *AzureStore) AddTLSChallenge(domain string, cert *acme.Certificate) error {
	b, err := json.Marshal(cert)
	if err != nil {
		return err
	}

	entity := &ChallengeEntity{
		PartitionKey: httpChallengePartition,
		RowKey:       domain,
		ETag:         "*",
		Data:         base64.StdEncoding.EncodeToString(b),
	}

	data, err := json.Marshal(entity)
	if err != nil {
		return err
	}

	return s.client.SaveRow(httpChallengePartition, domain, data)
}

func (s *AzureStore) GetTLSChallenge(domain string) (*acme.Certificate, error) {
	data, err := s.client.GetRow(httpChallengePartition, domain)
	if err != nil {
		return nil, err
	}

	entity := &ChallengeEntity{}
	err = json.Unmarshal(data, entity)
	if err != nil {
		return nil, err
	}

	b, err := base64.StdEncoding.DecodeString(entity.Data)
	if err != nil {
		return nil, err
	}

	cert := &acme.Certificate{}
	err = json.Unmarshal(b, cert)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (s *AzureStore) RemoveTLSChallenge(domain string) error {
	return s.client.DeleteRow(httpsChallengePartition, domain)
}

func (s *AzureStore) loadData() {
	logger := log.WithoutContext()

	data, err := s.client.GetPartition(accountPartition)
	if err != nil {
		logger.Error("Failed to fetch accounts from Azure Table Storage")
		return
	}

	result := map[string][]*AccountEntity{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		logger.Error("Failed to decode accounts from Azure Table Storage: ", err)
		return
	}

	accountList, ok := result["value"]
	if !ok {
		logger.Error("Unexpected response from Azure Table Storage", string(data))
		return
	}

	accounts := map[string]*AccountEntity{}
	certs := map[string][]*CertificateEntity{}
	for _, a := range accountList {
		accounts[a.RowKey] = a
		certs[a.RowKey], err = s.loadCerts(a.RowKey)
		if err != nil {
			logger.Error("Failed to load certs: ", err)
			return
		}
	}

	if s.isChanged(accounts, certs) {
		s.lock.Lock()
		defer s.lock.Unlock()

		s.accounts = accounts
		s.certs = certs
	}
}

func (s *AzureStore) isChanged(accounts map[string]*AccountEntity, certs map[string][]*CertificateEntity) bool {
	return false
}

func (s *AzureStore) loadCerts(providerName string) ([]*CertificateEntity, error) {
	return nil, nil
}
