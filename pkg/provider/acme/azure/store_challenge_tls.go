package azure

import (
	"encoding/base64"
	"encoding/json"
	"github.com/containous/traefik/v2/pkg/provider/acme"
	"github.com/containous/traefik/v2/pkg/types"
)

func (s *TableStore) AddTLSChallenge(domain string, cert *acme.Certificate) error {
	sansJSon, err := json.Marshal(cert.Domain.SANs)
	if err != nil {
		return err
	}

	entity := &TlsChallengeEntity{
		PartitionKey:      httpChallengePartition,
		RowKey:            domain,
		ETag:              "*",
		DomainMain:        cert.Domain.Main,
		DomainSansJson:    string(sansJSon),
		CertificateBase64: base64.StdEncoding.EncodeToString(cert.Certificate),
		KeyBase64:         base64.StdEncoding.EncodeToString(cert.Key),
	}

	data, err := json.Marshal(entity)
	if err != nil {
		return err
	}

	return s.client.SaveRow(httpChallengePartition, domain, data)
}

func (s *TableStore) GetTLSChallenge(domain string) (*acme.Certificate, error) {
	data, err := s.client.GetRow(httpChallengePartition, domain)
	if err != nil {
		return nil, err
	}

	entity := &TlsChallengeEntity{}
	err = json.Unmarshal(data, entity)
	if err != nil {
		return nil, err
	}

	sans := &[]string{}
	err = json.Unmarshal([]byte(entity.DomainSansJson), sans)
	if err != nil {
		return nil, err
	}

	cert, err := base64.StdEncoding.DecodeString(entity.CertificateBase64)
	if err != nil {
		return nil, err
	}

	key, err := base64.StdEncoding.DecodeString(entity.KeyBase64)
	if err != nil {
		return nil, err
	}

	result := &acme.Certificate{
		Domain: types.Domain{
			Main: entity.DomainMain,
			SANs: *sans,
		},
		Certificate: cert,
		Key: key,
	}

	return result, nil
}

func (s *TableStore) RemoveTLSChallenge(domain string) error {
	return s.client.DeleteRow(httpsChallengePartition, domain)
}
