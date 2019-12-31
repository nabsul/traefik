package azure

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	account string
	key     string
	table   string
}

func NewClient(account, key, table string) *Client {
	return &Client{
		account: account,
		key:     key,
		table:   table,
	}
}

func (s *Client) GetPartition(partition string) ([]byte, error) {
	filter := url.QueryEscape(fmt.Sprintf("PartitionKey eq '%s'", partition))
	path := fmt.Sprintf("/%s()?filter=%s", s.table, filter)
	return s.Query(path)
}

func (s *Client) GetRow(partition, row string) ([]byte, error) {
	path := fmt.Sprintf("/%s(PartitionKey='%s',RowKey='%s')", s.table, partition, row)
	return s.Query(path)
}

func (s *Client) DeleteRow(partition, row string) error {
	path := fmt.Sprintf("/%s(PartitionKey='%s',RowKey='%s')", s.table, partition, row)
	_, err := s.makeRequest("DELETE", path, nil)
	return err
}

func (s *Client) SaveRow(partition, row string, data []byte) error {
	path := fmt.Sprintf("/%s(PartitionKey='%s',RowKey='%s')", s.table, partition, row)
	_, err := s.makeRequest("PUT", path, data)
	return err
}

func (s *Client) Query(path string) ([]byte, error) {
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

func (s *Client) makeRequest(verb, path string, body []byte) (*http.Response, error) {
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

func (s *Client) getAuthHeader(date, verb, path string, body []byte) (string, error) {
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
