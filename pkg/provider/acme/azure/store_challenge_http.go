package azure

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func getHttpChallengeRowId(token, domain string) string {
	return fmt.Sprintf("%s_%s", token, domain)
}

func (s *TableStore) GetHTTPChallengeToken(token, domain string) ([]byte, error) {
	data, err := s.client.GetRow(httpChallengePartition, getHttpChallengeRowId(token, domain))
	if err != nil {
		return nil, err
	}

	entity := &HttpChallengeEntity{}
	err = json.Unmarshal(data, entity)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(entity.TokenBase64)
}

func (s *TableStore) SetHTTPChallengeToken(token, domain string, keyAuth []byte) error {
	entity := &HttpChallengeEntity{
		PartitionKey: httpChallengePartition,
		RowKey:       getHttpChallengeRowId(token, domain),
		ETag:         "*",
		TokenBase64:  base64.StdEncoding.EncodeToString(keyAuth),
	}

	data, err := json.Marshal(entity)
	if err != nil {
		return err
	}

	return s.client.SaveRow(httpChallengePartition, getHttpChallengeRowId(token, domain), data)
}

func (s *TableStore) RemoveHTTPChallengeToken(token, domain string) error {
	rowId := fmt.Sprintf("%s_%s", token, domain)
	return s.client.DeleteRow(httpChallengePartition, rowId)
}
