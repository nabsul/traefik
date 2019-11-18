package acme

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/registration"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const refreshTime = int64(time.Minute * 10)
const accountPartition = "accounts"
const httpChallengePartition = "http_challenge"
const httpsChallengePartition = "https_challenge"

type AzureStore struct {
	account     string
	key         string
	table       string
	nextRefresh int64
	lock        sync.RWMutex
	storedData  map[string]*StoredData
}

func NewAzureStore(account, key, table string) *AzureStore {
	return &AzureStore{account: account, key: key, table: table, nextRefresh: 0}
}

func (s *AzureStore) GetAccount(a string) (*Account, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	err := s.refreshIfNeeded()
	if err != nil {
		return nil, err
	}

	result, ok := s.storedData[a]
	if !ok {
		return nil, errors.New("account not found: " + a)
	}

	return result.Account, nil
}

func (s *AzureStore) SaveAccount(id string, a *Account) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	entity, err := s.convertToAccountEntity(id, a)
	if err != nil {
		return err
	}

	entity.PartitionKey = accountPartition
	entity.RowKey = id
	data, err := json.Marshal(entity)
	if err != nil {
		return err
	}

	err = s.saveRow(entity.PartitionKey, entity.RowKey, data)
	if err != nil {
		return err
	}
	
	s.storedData[id] = &StoredData{
		Account:      a,
		Certificates: nil,
	}

	return nil
}

func (s *AzureStore) GetCertificates(id string) ([]*CertAndStore, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	err := s.refreshIfNeeded()
	if err != nil {
		return nil, err
	}

	store, ok := s.storedData[id]
	if !ok {
		return nil, errors.New("account not found: " + id)
	}

	return store.Certificates, nil
}

func (s *AzureStore) SaveCertificates(id string, certs []*CertAndStore) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	acct, ok := s.storedData[id]
	if !ok {
		acct = &StoredData{
			Account:      nil,
			Certificates: certs,
		}
	} else {
		acct.Certificates = certs
	}

	entity, err := s.convertToAccountEntity(id, acct.Account)
	if err != nil {
		return err
	}

	data, err := json.Marshal(entity)
	if err != nil {
		return err
	}

	return s.saveRow(accountPartition, id, data)
}

type AzureChallengeEntity struct {
	PartitionKey, RowKey, ETag string
	Token string
}

func (s *AzureStore) GetHTTPChallengeToken(token, domain string) ([]byte, error) {
	rowId := fmt.Sprintf("%s_%s", token, domain)
	data, err := s.getRow(httpChallengePartition, rowId)
	if err != nil {
		return nil, err
	}

	entity := &AzureChallengeEntity{}
	err = json.Unmarshal(data, entity)
	if err != nil {
		return nil, err
	}

	b, err := base64.StdEncoding.DecodeString(entity.Token)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (s *AzureStore) SetHTTPChallengeToken(token, domain string, keyAuth []byte) error {
	rowId := fmt.Sprintf("%s_%s", token, domain)
	entity := &AzureChallengeEntity{
		PartitionKey: httpChallengePartition,
		RowKey:       rowId,
		ETag:         "",
		Token:        base64.StdEncoding.EncodeToString(keyAuth),
	}

	data, err := json.Marshal(entity)
	if err != nil {
		return err
	}

	return s.saveRow(httpChallengePartition, rowId, data)
}

func (s *AzureStore) RemoveHTTPChallengeToken(token, domain string) error {
	rowId := fmt.Sprintf("%s_%s", token, domain)
	return s.deleteRow(httpChallengePartition, rowId)
}

func (s *AzureStore) AddTLSChallenge(domain string, cert *Certificate) error {
	return nil
}

func (s *AzureStore) GetTLSChallenge(domain string) (*Certificate, error) {
	return nil, nil
}

func (s *AzureStore) RemoveTLSChallenge(domain string) error {
	return nil
}

func (s *AzureStore) convertToAccount(acct AzureAccountEntity) (*Account, error) {
	key, err := base64.StdEncoding.DecodeString(acct.PrivateKey)
	if err != nil {
		return nil, err
	}

	reg := &registration.Resource{}
	regBytes, err := base64.StdEncoding.DecodeString(acct.RegistrationJson)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(regBytes, reg)
	if err != nil {
		return nil, err
	}

	return &Account{
		Email: acct.Email,
		Registration: reg,
		PrivateKey: key,
		KeyType: certcrypto.KeyType(acct.KeyType),
	}, nil
}

func (s *AzureStore) convertToAccountEntity(id string, acct *Account) (*AzureAccountEntity, error) {
	regBytes, err := json.Marshal(acct.Registration)
	if err != nil {
		return nil, err
	}
	regStr := base64.StdEncoding.EncodeToString(regBytes)

	return &AzureAccountEntity{
		Email:            acct.Email,
		RegistrationJson: regStr,
		PrivateKey:       base64.StdEncoding.EncodeToString(acct.PrivateKey),
		KeyType:          string(acct.KeyType),
	}, nil
}

func (s *AzureStore) getPartition(partition string) ([]byte, error) {
	filter := url.QueryEscape(fmt.Sprintf("PartitionKey eq '%s'", partition))
	path := fmt.Sprintf("/%s()?filter=%s", s.table, filter)
	return s.query(path)
}

func (s *AzureStore) getRow(partition, row string) ([]byte, error) {
	path := fmt.Sprintf("/%s(PartitionKey='%s',RowKey='%s')", s.table, partition, row)
	return s.query(path)
}

func (s *AzureStore) deleteRow(partition, row string) error {
	path := fmt.Sprintf("/%s(PartitionKey='%s',RowKey='%s')", s.table, partition, row)
	_, err := s.makeRequest("DELETE", path, nil)
	return err
}

func (s *AzureStore) saveRow(partition, row string, data []byte) error {
	path := fmt.Sprintf("/%s(PartitionKey='%s',RowKey='%s')", s.table, partition, row)
	_, err := s.makeRequest("PUT", path, data)
	return err
}

func (s *AzureStore) query(path string) ([]byte, error) {
	response, err := s.makeRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(response.Body)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *AzureStore) makeRequest(verb, path string, body []byte) (*http.Response, error) {
	date := time.Now().UTC().Format(http.TimeFormat)
	u := fmt.Sprintf("https://%s.table.core.windows.net%s", s.account, path)
	fmt.Println(u)

	auth, err := s.getAuthHeader(date, verb, path, body)
	if err != nil {
		return nil, err
	}


	req, err := http.NewRequest(verb, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Add("x-ms-date", date)
	req.Header.Add("Authorization", auth)
	req.Header.Add("Accept", "application/json;odata=nometadata")
	if body != nil && len(body) > 0 {
		req.Header.Add("Content-Type", "application/json")
	}
	req.Header.Add("x-ms-version", "2015-04-05")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return nil, err
	}
	fmt.Println(buf.String())
	resp.Body = ioutil.NopCloser(bytes.NewReader(buf.Bytes()))

	return resp, nil
}

func (s *AzureStore) getAuthHeader(date, verb, path string, body []byte) (string, error) {
	path = strings.Split(path, "?")[0]
	canonicalResource := fmt.Sprintf("/%s%s", s.account, path)

	contentMd5 := ""
	contentType := ""
	if body != nil && len(body) > 0 {
		contentType = "application/json"
	}

	parts := []string{verb, contentMd5, contentType, date, canonicalResource}
	stringToSign := strings.Join(parts, "\n")
	jsonStr, _ := json.Marshal(stringToSign)
	fmt.Println("StringToSign: " + string(jsonStr))

	keyBytes, err := base64.StdEncoding.DecodeString(s.key)
	if err != nil {
		return "", err
	}

	h := hmac.New(sha256.New, keyBytes)
	bytesToSign := []byte(stringToSign)
	n, err := h.Write(bytesToSign)
	if err != nil {
		return "", err
	}
	if n != len(bytesToSign) {
		return "", errors.New("signing didn't fully complete")
	}
	sha := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("SharedKey %s:%s", s.account, sha), nil
}

func (s *AzureStore) refreshIfNeeded() error {
	now := time.Now().Unix()
	if now < s.nextRefresh {
		return nil
	}

	data, err := s.getPartition(accountPartition)
	if err != nil {
		return err
	}

	var result = map[string][]AzureAccountEntity{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return err
	}

	accounts, ok := result["value"]
	if !ok {
		return errors.New("query for accounts returned unexpected result")
	}

	newAccounts := map[string]*StoredData{}

	for _, acct := range accounts {
		result, err := s.convertToAccount(acct)
		if err != nil {
			return err
		}

		newAccounts[acct.RowKey] = &StoredData{
			Account:      result,
			Certificates: nil,
		}
	}

	s.nextRefresh = now + refreshTime
	return nil
}

type AzureAccountEntity struct {
	PartitionKey, RowKey, ETag string
	Email                      string
	RegistrationJson           string
	PrivateKey                 string
	KeyType                    string
}
