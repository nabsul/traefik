package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/safe"
	"sync"
	"time"
)

const refreshTime = 10 * time.Minute
const accountPartition = "accounts"
const certificatePartition = "certificates"
const httpChallengePartition = "http_challenge"
const httpsChallengePartition = "https_challenge"

type TableStore struct {
	pool               *safe.Pool
	client             *Client
	account            string
	key                string
	table              string
	nextRefresh        int64
	lock               sync.RWMutex
	accounts           map[string]*AccountEntity
	certs              map[string][]*CertificateEntity
	changeNotification chan bool
	logger             log.Logger
}

func NewAzureStore(account, key, table string, pool *safe.Pool) *TableStore {
	fields := log.Str(log.ProviderName, fmt.Sprintf("Azure:%s:%s", account, table))
	ctx := log.With(context.Background(), fields)
	logger := log.FromContext(ctx)

	s := &TableStore{
		pool:        pool,
		client:      NewClient(account, key, table),
		nextRefresh: 0,
		accounts:    make(map[string]*AccountEntity),
		certs:       make(map[string][]*CertificateEntity),
		logger:      logger,
	}

	s.loadData()

	if pool == nil {
		return s
	}

	ticker := time.NewTicker(refreshTime)
	s.pool.Go(func(stop chan bool) {
		for {
			select {
			case <-ticker.C:
				s.logger.Debug("Refreshing certs")
				s.loadData()
				return
			case <-stop:
				s.logger.Debug("Azure provider is stopping")
				ticker.Stop()
				return
			}
		}
	})

	return s
}

func (s *TableStore) SetNotificationChannel(c chan bool) {
	s.changeNotification = c
}

func (s *TableStore) loadData() {
	data, err := s.client.GetPartition(accountPartition)
	if err != nil {
		s.logger.Error("Failed to fetch accounts from Azure Table Storage")
		return
	}

	result := map[string][]*AccountEntity{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		s.logger.Error("Failed to decode accounts from Azure Table Storage: ", err)
		return
	}

	accountList, ok := result["value"]
	if !ok {
		s.logger.Error("Unexpected response from Azure Table Storage", string(data))
		return
	}

	accounts := map[string]*AccountEntity{}
	certs := map[string][]*CertificateEntity{}
	for _, a := range accountList {
		accounts[a.RowKey] = a
		certs[a.RowKey], err = s.loadCerts(a.RowKey)
		if err != nil {
			s.logger.Error("Failed to load certs: ", err)
			return
		}
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	eq, err := areEqual(s.accounts, accounts, s.certs, certs)
	if err != nil {
		s.logger.Error("Failed to compare old and new account/cert data: ", err)
		return
	}

	if !eq {
		s.logger.Info("Data has changed in Azure. Updating.")
		s.accounts = accounts
		s.certs = certs
		if s.changeNotification != nil {
			s.changeNotification<- true
		}
	} else {
		s.logger.Info("No change in data since last load.")
	}
}

func areEqual(oldAccounts, newAccounts map[string]*AccountEntity, oldCerts, newCerts map[string][]*CertificateEntity) (bool, error) {
	if len(oldAccounts) != len(newAccounts) || len(oldCerts) != len(newCerts) {
		return false, nil
	}

	for k, l := range oldAccounts {
		r, ok := newAccounts[k]
		if !ok {
			return false, nil
		}

		equal, err := areEqualJson(l, r)
		if err != nil {
			return false, err
		}

		if !equal {
			return false, nil
		}
	}

	for k, l := range oldCerts {
		r, ok := newCerts[k]
		if !ok {
			return false, nil
		}

		equal, err := areEqualJson(l, r)
		if err != nil {
			return false, err
		}

		if !equal {
			return false, nil
		}
	}

	return true, nil
}

func areEqualJson(left, right interface{}) (bool, error) {
	leftBytes, err := json.Marshal(left)
	if err != nil {
		return false, err
	}

	rightBytes, err := json.Marshal(right)
	if err != nil {
		return false, err
	}

	return bytes.Compare(leftBytes, rightBytes) == 0, nil
}

func (s *TableStore) loadCerts(providerName string) ([]*CertificateEntity, error) {
	return nil, nil
}
