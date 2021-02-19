package tdl

import (
	"strings"
)

// decompose a path into parents and leaf.
// for example: a.b.c -> [a, b], c
func decompose(path string) (parents []string, leaf string) {
	if !strings.ContainsRune(path, '.') {
		leaf = path
	} else {
		parents = strings.Split(path, ".")
		leaf = parents[len(parents)-1]
		parents = parents[:len(parents)-1]
	}
	return parents, leaf
}

// getFormatted returns a map with formatted unconstructed types.
func getFormatted(unconstructedTypes map[string]UnconstructedTdlTypeIF) map[string]*TdlFormattedType {
	formatted := make(map[string]*TdlFormattedType)
	for k := range unconstructedTypes {
		tdlType := unconstructedTypes[k]
		formatted[k] = tdlType.FormatTdlType()
	}
	return formatted
}

// BuildJson builds the initial formatted json.
func BuildJson(unconstructedTypes map[string]UnconstructedTdlTypeIF) map[string]interface{} {
	formatted := getFormatted(unconstructedTypes)

	json := make(map[string]interface{})
	for path := range formatted {
		parents, leaf := decompose(path)
		parentJson := json
		for _, parent := range parents {
			if _, ok := parentJson[parent]; !ok {
				parentJson[parent] = make(map[string]interface{})
			}
			parentJson = parentJson[parent].(map[string]interface{})
		}
		parentJson[leaf] = formatted[path]
	}
	return json
}

// UpdateJson updates the formatted json with new values
func UpdateJson(unconstructedTypes map[string]UnconstructedTdlTypeIF, json map[string]interface{}) map[string]interface{} {
	formatted := getFormatted(unconstructedTypes)
	for path := range formatted {
		parents, leaf := decompose(path)
		parentJson := json
		for _, parent := range parents {
			parentJson = parentJson[parent].(map[string]interface{})
		}
		parentJson[leaf] = formatted[path]
	}
	return json
}
