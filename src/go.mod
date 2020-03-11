module github.com/my/repo

go 1.13

replace emu => ../src/emu

replace external => ../src/external

replace external/google/gopacket => ../src/external/google/gopacket

require (
	emu v0.0.0-00010101000000-000000000000
	external v0.0.0-00010101000000-000000000000 // indirect
	external/google/gopacket v0.0.0-00010101000000-000000000000 // indirect
	github.com/akamensky/argparse v1.2.0 // indirect
	github.com/go-playground/validator/v10 v10.0.1 // indirect
	gopkg.in/go-playground/assert.v1 v1.2.1 // indirect
)
