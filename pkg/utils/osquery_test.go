package utils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryRows(t *testing.T) {
	query := "SELECT * FROM table"
	clienter := &MockOsqueryClienter{
		Data: map[string][]map[string]string{
			query: {{"column1": "value1", "column2": "value2"}},
		},
	}

	mock, err := clienter.NewOsqueryClient()
	require.NoError(t, err)

	data, err := mock.QueryRows(query)
	require.NoError(t, err)
	assert.Equal(t, clienter.Data[query], data)
}

func TestQueryRow(t *testing.T) {
	query := "SELECT * FROM table"
	clienter := &MockOsqueryClienter{
		Data: map[string][]map[string]string{
			query: {{"column1": "value1", "column2": "value2"}},
		},
	}

	mock, err := clienter.NewOsqueryClient()
	require.NoError(t, err)

	data, err := mock.QueryRow("SELECT * FROM table")
	require.NoError(t, err)
	assert.Equal(t, clienter.Data[query][0], data)

	_, err = mock.QueryRow("SELECT * FROM unanswered")
	assert.ErrorContains(t, err, "expected 1 row, got 0")
}

func TestQueryRowContext(t *testing.T) {
	query := "SELECT * FROM table"
	mock := &MockOsqueryClient{Data: map[string][]map[string]string{query: {{"column1": "value1"}}}}

	data, err := mock.QueryRowContext(context.Background(), query)
	require.NoError(t, err)
	assert.Equal(t, mock.Data[query][0], data)

	_, err = mock.QueryRowContext(context.Background(), "SELECT * FROM unanswered")
	assert.ErrorContains(t, err, "expected 1 row, got 0")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = mock.QueryRowContext(ctx, query)
	assert.ErrorIs(t, err, context.Canceled)
}
