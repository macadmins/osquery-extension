package utils

import (
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
}
