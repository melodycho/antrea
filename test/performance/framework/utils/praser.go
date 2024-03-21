package utils

import (
	"fmt"
	"io/ioutil"
	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
)

func ReadYamlFile(yamlFile string) (runtime.Object, error) {
	klog.InfoS("ReadYamlFile", "yamlFile", yamlFile)
	podBytes, err := ioutil.ReadFile(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("error reading YAML file: %+v", err)
	}

	decoder := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
	obj, _, err := decoder.Decode(podBytes, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error decoding YAML file: %+v", err)
	}
	return obj, nil
}
