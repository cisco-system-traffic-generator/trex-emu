package ipfix

import (
	"emu/core"
	engines "emu/plugins/field_engine"
	"errors"
	"fmt"

	"github.com/intel-go/fastjson"
)

// A wrapper to a field engine used by auto-triggered devices to generate clients IPv4 addresses with a
// given range and repetition.
// As an example, let's consider the following clients generator params JSON:
// "clients_generator": {
//     "client_ipv4_field_name": "clientIPv4Address",
//     "client_ipv4": [1,1,1,1],
// .   "clients_per_device": 48,
// .   "data_records_per_client": 41
// }
// This JSON will replace "clientIPv4Address" field (if exists) in the device's init JSON with the following JSON.
// Field definition:
// {
//     "name": "clientIPv4Address",
//     "type": 45004,
//     "length": 4,
//     "enterprise_number": 9,
//     "data": [1,1,1,1]
// }
// Engine definition:
// {
//     "engine_type": "uint",
//     "engine_name": "%v",
//     "params":
//     {
//         "size": 4,
//         "offset": 0,
//         "op": "inc",
//         "repeat":41,
//         "min": 16843009,
//         "max": 16843056,
//     }
// }
type ClientsGen struct {
	clientIpv4FieldName  string
	clientIpv4           core.Ipv4Key
	clientsPerDevice     uint32
	dataRecordsPerClient uint32

	field  *IPFixField
	engine engines.FieldEngineIF
}

const (
	defaultClientIpv4AddressFieldName = "clientIPv4Address"
	Ipv4AddressFieldType              = 45004
	Ipv4AddressFieldLength            = 4
	Ipv4AddressFieldEntNum            = 9
)

type ClientsGenParams struct {
	ClientIpv4FieldName  string       `json:"client_ipv4_field_name"`                      // IPFIX record field name to replace with a dynamic clients-generator field. Optional. Default: "clientIPv4Address".
	ClientIpv4           core.Ipv4Key `json:"client_ipv4" validate:"required"`             // The first IPv4 used by this generator.
	ClientsPerDevice     uint32       `json:"clients_per_device" validate:"required"`      // Number of IPs to generate.
	DataRecordsPerClient uint32       `json:"data_records_per_client" validate:"required"` // Number of times each IP address is repeated.
}

func (p *ClientsGenParams) String() string {
	s := fmt.Sprintln("\nClients generator params: ")
	s += fmt.Sprintln("\tClientIpv4FieldName -", p.ClientIpv4FieldName)
	s += fmt.Sprintln("\tClientIpv4 -", p.ClientIpv4.ToIP())
	s += fmt.Sprintln("\tClientsPerDevice -", p.ClientsPerDevice)
	s += fmt.Sprintln("\tDataRecordsPerClient -", p.DataRecordsPerClient)
	return s
}

type clientsGenEngines struct {
	Engines *fastjson.RawMessage `json:"engines"`
}

func UnmarshalClientsGenParams(ipfixNs *IpfixNsPlugin, clientsGenParams *fastjson.RawMessage) (*ClientsGenParams, error) {
	if ipfixNs == nil {
		return nil, errors.New("Invalid NS context parameter")
	}

	if clientsGenParams == nil {
		return nil, errors.New("Invalid 'clientsGenParams' parameter")
	}

	params := &ClientsGenParams{ClientIpv4FieldName: defaultClientIpv4AddressFieldName}

	err := ipfixNs.Tctx.UnmarshalValidate(*clientsGenParams, params)
	if err != nil {
		return nil, err
	}

	if params.ClientsPerDevice == 0 {
		return nil, errors.New("Invalid 'ClientsPerDevice' clients generator param")
	}

	if params.DataRecordsPerClient == 0 {
		return nil, errors.New("Invalid 'DataRecordsPerClient' clients generator param")
	}

	return params, nil
}

func NewClientsGen(ipfix *PluginIPFixClient, params *ClientsGenParams) (*ClientsGen, error) {
	if ipfix == nil {
		return nil, errors.New("Invalid IPFIX client context parameter")
	}

	if params == nil {
		return nil, errors.New("Invalid clients generator params parameter")
	}

	clientsGen := new(ClientsGen)
	clientsGen.clientIpv4FieldName = params.ClientIpv4FieldName
	clientsGen.clientIpv4 = params.ClientIpv4
	clientsGen.clientsPerDevice = params.ClientsPerDevice
	clientsGen.dataRecordsPerClient = params.DataRecordsPerClient

	field := new(IPFixField)
	field.Name = params.ClientIpv4FieldName
	field.Type = Ipv4AddressFieldType
	field.Length = Ipv4AddressFieldLength
	field.EnterpriseNumber = Ipv4AddressFieldEntNum
	field.Data = params.ClientIpv4[:]
	clientsGen.field = field

	min_ip := params.ClientIpv4.Uint32()
	max_ip := params.ClientIpv4.Uint32() + params.ClientsPerDevice - 1

	engines_json_str := fmt.Sprintf(`{"engines": [
		{
		"engine_type": "uint",
		"engine_name": "%v",
		"params":
			{
				"size": 4,
				"offset": 0,
				"op": "inc",
				"repeat":%v,
				"min": %v,
				"max": %v,
			}
		 }
	 ]}`, field.Name, params.DataRecordsPerClient, min_ip, max_ip)

	engines_json := clientsGenEngines{}
	err := ipfix.Tctx.UnmarshalValidate([]byte(engines_json_str), &engines_json)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse engine JSON string: %w", err)
	}

	engineMgr, err := engines.NewEngineManager(ipfix.Tctx, engines_json.Engines)
	if err != nil {
		return nil, fmt.Errorf("Failed to create engine manager: %w", err)
	}

	clientsGen.engine = engineMgr.GetEngineMap()[clientsGen.GetClientIpv4FieldName()]

	return clientsGen, nil
}

func (p *ClientsGen) GetClientIpv4FieldName() string {
	return p.clientIpv4FieldName
}

func (p *ClientsGen) GetField() *IPFixField {
	return p.field
}

func (p *ClientsGen) GetEngine() engines.FieldEngineIF {
	return p.engine
}
