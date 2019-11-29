package azure

import (
	"encoding/base64"
	"encoding/json"
	"github.com/containous/traefik/v2/pkg/provider/acme"
	"github.com/containous/traefik/v2/pkg/types"
)

type CertificateEntity struct {
	PartitionKey, RowKey, ETag string
	MainDomain                 string
	SANsJson                   string
	CertificateBase64          string
	KeyBase64                  string
	Store                      string
}

func (cert *CertificateEntity) Convert() (*acme.CertAndStore, error) {
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

func NewCert(cert *acme.CertAndStore) (*CertificateEntity, error) {
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
