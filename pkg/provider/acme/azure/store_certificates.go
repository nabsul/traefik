package azure

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containous/traefik/v2/pkg/provider/acme"
	"github.com/containous/traefik/v2/pkg/types"
)

func (s *TableStore) GetCertificates(resolverName string) ([]*acme.CertAndStore, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	certs, ok := s.certs[resolverName]
	if !ok {
		return nil, errors.New("Account not found for resolver: " + resolverName)
	}

	result := make([]*acme.CertAndStore, len(certs))
	for i, c := range certs {
		converted, err := convertCertEntity(c)
		if err != nil {
			return nil, err
		}
		result[i] = converted
	}

	return result, nil
}

func convertCertEntity(cert *CertificateEntity) (*acme.CertAndStore, error) {
	sans := &[]string{}
	err := json.Unmarshal([]byte(cert.SANsJson), sans)
	if err != nil {
		return nil, err
	}

	certificate, err := base64.StdEncoding.DecodeString(cert.CertificateBase64)
	if err != nil {
		return nil, err
	}

	key, err := base64.StdEncoding.DecodeString(cert.KeyBase64)
	if err != nil {
		return nil, err
	}

	return &acme.CertAndStore{
		Certificate: acme.Certificate{
			Domain: types.Domain{
				Main: cert.MainDomain,
				SANs: *sans,
			},
			Certificate: certificate,
			Key:         key,
		},
		Store: cert.Store,
	}, nil
}

func (s *TableStore) SaveCertificates(resolverName string, certs []*acme.CertAndStore) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	certEntities := make([]*CertificateEntity, len(certs))
	for i, c := range certs {
		e, err := newCert(c)
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

func newCert(cert *acme.CertAndStore) (*CertificateEntity, error) {
	sansBytes, err := json.Marshal(cert.Domain.SANs)
	if err != nil {
		return nil, err
	}

	return &CertificateEntity{
		PartitionKey:      "",
		RowKey:            "",
		ETag:              "",
		MainDomain:        cert.Domain.Main,
		SANsJson:          string(sansBytes),
		CertificateBase64: base64.StdEncoding.EncodeToString(cert.Certificate.Certificate),
		KeyBase64:         base64.StdEncoding.EncodeToString(cert.Key),
		Store:             cert.Store,
	}, nil
}
