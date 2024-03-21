package framework

import (
	utils2 "antrea.io/antrea/test/performance/framework/utils"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestRenderService(t *testing.T) {
	var err error
	defer func() {
		fmt.Println(err)
	}()
	obj, err := utils2.ReadYamlFile("../../assets/service/service.yaml")
	if err != nil {
		err = fmt.Errorf("error reading Service template: %+v", err)
		return
	}

	fmt.Println(obj, "0000")

	service, ok := obj.(*corev1.Service)
	if !ok {
		err = fmt.Errorf("error converting to Unstructured: %+v", err)
		return
	}
	fmt.Println(service)
}
