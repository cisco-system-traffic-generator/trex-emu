module github.com/my/repo

go 1.18

replace emu => ../src/emu

replace external => ../src/external

replace external/google/gopacket => ../src/external/google/gopacket

require (
	emu v0.0.0-00010101000000-000000000000
	github.com/akamensky/argparse v1.2.0
	github.com/davecgh/go-spew v1.1.1
	github.com/pmezard/go-difflib v1.0.0
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	golang.org/x/tools v0.0.0-20180917221912-90fa682c2a6e
	gopkg.in/yaml.v2 v2.2.2
)

require (
	external v0.0.0-00010101000000-000000000000 // indirect
	external/google/gopacket v0.0.0-00010101000000-000000000000 // indirect
	github.com/alecthomas/jsonschema v0.0.0-20200217214135-7152f22193c9 // indirect
	github.com/go-playground/locales v0.13.0 // indirect
	github.com/go-playground/universal-translator v0.17.0 // indirect
	github.com/go-playground/validator v9.31.0+incompatible // indirect
	github.com/iancoleman/orderedmap v0.0.0-20190318233801-ac98e3ecb4b0 // indirect
	github.com/intel-go/fastjson v0.0.0-20170329170629-f846ae58a1ab // indirect
	github.com/leodido/go-urn v1.2.0 // indirect
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
)
