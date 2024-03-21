package framework

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderService(t *testing.T) {
	obj, err := unmarshallService("../assets/service/service.yaml")
	assert.NoError(t, err, "error reading Service template")
	fmt.Println(obj)
}
