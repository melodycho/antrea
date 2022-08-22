package pkg

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAdd(t *testing.T) {
	assert.Equal(t, 2, add(1, 1))
}
