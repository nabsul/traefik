package azure

type AccountEntity struct {
	PartitionKey, RowKey, ETag string
	Email                      string
	RegistrationJson           string
	PrivateKey                 string
	KeyType                    string
}

type CertificateEntity struct {
	PartitionKey, RowKey, ETag string
	MainDomain                 string
	SANsJson                   string
	CertificateBase64          string
	KeyBase64                  string
	Store                      string
}

type HttpChallengeEntity struct {
	PartitionKey, RowKey, ETag string
	TokenBase64                string
}

type TlsChallengeEntity struct {
	PartitionKey, RowKey, ETag string
	DomainMain                 string
	DomainSansJson             string
	CertificateBase64          string
	KeyBase64                  string
}
