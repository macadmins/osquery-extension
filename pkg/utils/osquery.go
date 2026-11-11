package utils

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/osquery/osquery-go"
)

type OsqueryClienter interface {
	NewOsqueryClient() (OsqueryClient, error)
}

// OsqueryClient is the part of osquery-go's *ExtensionManagerClient the tables use. The context
// forms bound the wait for the client's lock by the table's own query; they do not stop a query
// once the lock is held, so a caller checks ctx.Err() first.
type OsqueryClient interface {
	QueryRows(query string) ([]map[string]string, error)
	QueryRow(query string) (map[string]string, error)
	QueryRowsContext(ctx context.Context, query string) ([]map[string]string, error)
	QueryRowContext(ctx context.Context, query string) (map[string]string, error)
	Close()
}

// SocketClienter opens clients on osquery's extension socket at socketPath, with the timeout
// every table uses.
func SocketClienter(socketPath string) OsqueryClienter {
	return &SocketOsqueryClienter{SocketPath: socketPath, Timeout: 10 * time.Second}
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
	// Err, when set, is returned in place of a client, as when the socket cannot be reached.
	Err error
}

func (m *MockOsqueryClienter) NewOsqueryClient() (OsqueryClient, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return &MockOsqueryClient{Data: m.Data}, nil
}

type MockOsqueryClient struct {
	Data map[string][]map[string]string
}

func (m *MockOsqueryClient) QueryRows(query string) ([]map[string]string, error) {
	return m.Data[query], nil
}

// QueryRow answers with the query's one row, and fails otherwise, as osquery-go's QueryRow does.
func (m *MockOsqueryClient) QueryRow(query string) (map[string]string, error) {
	rows := m.Data[query]
	if len(rows) != 1 {
		return nil, fmt.Errorf("expected 1 row, got %d", len(rows))
	}
	return rows[0], nil
}

// QueryRowsContext answers as QueryRows does, or with the context's error once it is done.
func (m *MockOsqueryClient) QueryRowsContext(ctx context.Context, query string) ([]map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.QueryRows(query)
}

// QueryRowContext answers as QueryRow does, or with the context's error once it is done.
func (m *MockOsqueryClient) QueryRowContext(ctx context.Context,
	query string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.QueryRow(query)
}

func (m *MockOsqueryClient) Close() {}

// ErrorOsqueryClient fails every query with Err, for tests of the path where osquery cannot
// answer. With no Err it still fails, so its zero value is never a client that answers nothing.
type ErrorOsqueryClient struct {
	Err error
}

func (e ErrorOsqueryClient) err() error {
	if e.Err == nil {
		return errors.New("osquery query failed")
	}
	return e.Err
}

func (e ErrorOsqueryClient) QueryRows(string) ([]map[string]string, error) { return nil, e.err() }

func (e ErrorOsqueryClient) QueryRow(string) (map[string]string, error) { return nil, e.err() }

func (e ErrorOsqueryClient) QueryRowsContext(context.Context, string) ([]map[string]string, error) {
	return nil, e.err()
}

func (e ErrorOsqueryClient) QueryRowContext(context.Context, string) (map[string]string, error) {
	return nil, e.err()
}

func (e ErrorOsqueryClient) Close() {}

// CancelAfterQueryClienter opens Inner's clients wrapped so that each QueryRowsContext call, once
// answered, calls Cancel when it is set: a test's way to land a cancellation after a query
// returns, such as between the account roster and the first home. QueryRows and QueryRow pass
// through without cancelling. Opened counts the clients it opened.
type CancelAfterQueryClienter struct {
	Inner  OsqueryClienter
	Cancel context.CancelFunc
	Opened int
}

func (clienter *CancelAfterQueryClienter) NewOsqueryClient() (OsqueryClient, error) {
	client, err := clienter.Inner.NewOsqueryClient()
	if err != nil {
		return nil, err
	}
	clienter.Opened++
	return cancelAfterQuery{OsqueryClient: client, cancel: clienter.Cancel}, nil
}

type cancelAfterQuery struct {
	OsqueryClient
	cancel context.CancelFunc
}

func (client cancelAfterQuery) QueryRowsContext(ctx context.Context,
	query string) ([]map[string]string, error) {
	rows, err := client.OsqueryClient.QueryRowsContext(ctx, query)
	if client.cancel != nil {
		client.cancel()
	}
	return rows, err
}
