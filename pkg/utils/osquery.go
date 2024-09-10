package utils

import (
	"fmt"
	"time"

	"github.com/osquery/osquery-go"
)

type OsqueryClienter interface {
	NewOsqueryClient() (OsqueryClient, error)
}

type OsqueryClient interface {
	QueryRows(query string) ([]map[string]string, error)
	QueryRow(query string) (map[string]string, error)
	Close()
}

type SocketOsqueryClienter struct {
	SocketPath string
	Timeout    time.Duration
}

func (s *SocketOsqueryClienter) NewOsqueryClient() (OsqueryClient, error) {
	osqueryClient, err := osquery.NewClient(s.SocketPath, s.Timeout)
	if err != nil {
		return nil, fmt.Errorf("could not create osquery client: %w", err)
	}
	return osqueryClient, nil
}

type MockOsqueryClienter struct {
	Data map[string][]map[string]string
}

func (m *MockOsqueryClienter) NewOsqueryClient() (OsqueryClient, error) {
	return &MockOsqueryClient{Data: m.Data}, nil
}

type MockOsqueryClient struct {
	Data map[string][]map[string]string
}

func (m *MockOsqueryClient) QueryRows(query string) ([]map[string]string, error) {
	return m.Data[query], nil
}

func (m *MockOsqueryClient) QueryRow(query string) (map[string]string, error) {
	return m.Data[query][0], nil
}

func (m *MockOsqueryClient) Close() {}
