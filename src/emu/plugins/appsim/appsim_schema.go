// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package appsim

import (
	"encoding/json"
	"fmt"

	"github.com/intel-go/fastjson"
	"github.com/xeipuuv/gojsonschema"
)

const schema string = `{
    "title": "appsim",
    "description": "appsim",
    "type": "object",
    "properties": {
        "buf_list" : {
           "$ref": "#/definitions/buf_list_t"
        },
        "program_list" : {
            "$ref": "#/definitions/program_array_t"
        },

        "tunable_list" : {
            "$ref": "#/definitions/tunable_array_t"
        },

        "templates" : {
            "$ref": "#/definitions/template_array_t"
        }
    },
    
    "required": ["buf_list"],
    
    "definitions": {

             "buf_list_t" : {
                  "type": "array",
                  "items": {
                       "type": [ "string", "object" ]
                   }
              },

          
          "program_command_tx_t" : {
            "type": "object",
             "properties": {
                   "name": {
                       "type" : "string",
                       "enum": ["tx"]
                   },

                   "buf_index" : {
                       "type" : "integer"
                   }   
             },
             "required": ["name","buf_index"]
        },
             
       "program_command_rx_t" : {
            "type": "object",
             "properties": {
                   "name": {
                       "type" : "string",
                       "enum" : ["rx"]
                   },

                   "min_bytes" : {
                       "type" : "integer",
                       "minimum": 0
                   },

                   "clear" : {
                       "type" : "boolean"
                   }   
                      
             },
             "required": ["name","min_bytes"]
        },

       "program_command_keepalive_t" : {
            "type": "object",
             "properties": {
                   "name": {
                       "type" : "string",
                       "enum" : ["keepalive"]
                   },

                   "msec" : {
                       "type" : "integer",
                       "minimum": 0
                   },

                   "rx_mode" : {
                       "type" : "boolean"
                   }   
             },
             "required": ["name","msec"]
        },


       "program_command_rx_msg_t" : {
            "type": "object",
             "properties": {
                   "name": {
                       "type" : "string",
                       "enum" : ["rx_msg"]
                   },

                   "min_pkts" : {
                       "type" : "integer",
                       "minimum": 1
                   },

                   "clear" : {
                       "type" : "boolean"
                   }   
             },
             "required": ["name","min_pkts"]
        },
        
       "program_command_tx_msg_t" : {
            "type": "object",
             "properties": {
                   "name": {
                       "type" : "string",
                       "enum" : ["tx_msg"]
                   },

                   "buf_index" : {
                       "type" : "integer"
                   }   
             },
             "required": ["name","buf_index"]
        },

        
       "program_command_gen_t" : {
            "type": "object",
             "properties": {
                   "name": {
                       "type" : "string",
                       "enum" : ["close_msg","connect","reset","nc"]
                   }
             },
             "required": ["name"]
        },

       "program_command_delay_t" : {
            "type": "object",
             "properties": {
                   "name": {
                       "type" : "string",
                       "enum" : ["delay"]
                   },

                  "usec" : {
                       "type" : "integer",
                       "minimum": 1
                   }
             },
             "required": ["name","usec"]
        },

       "program_command_delay_rnd_t" : {
            "type": "object",
             "properties": {
                   "name": {
                       "type" : "string",
                       "enum" : ["delay_rnd"]
                   },

                  "min_usec" : {
                       "type" : "integer",
                       "minimum": 0
                   },

                  "max_usec" : {
                       "type" : "integer",
                       "minimum": 1
                   }
             },
             "required": ["name","min_usec","max_usec"]
        },

       "program_command_set_val_t" : {
            "type": "object",
             "properties": {
                   "name": {
                       "type" : "string",
                       "enum" : ["set_var"]
                   },

                  "id" : {
                       "type" : "integer"
                   },

                  "val" : {
                       "type" : "integer",
                       "minimum": 0
                   }
             },
             "required": ["name","id","val"]
        },

       "program_command_set_tick_var_t" : {
         "type": "object",
          "properties": {
                "name": {
                    "type" : "string",
                    "enum" : ["set_tick_var"]
                },

               "id" : {
                    "type" : "integer"
                }
          },
          "required": ["name", "id"]
         },

       "program_command_jmpnz_t" : {
            "type": "object",
             "properties": {
                   "name": {
                       "type" : "string",
                       "enum" : ["jmp_nz"]
                   },

                  "id" : {
                       "type" : "integer"
                   },

                  "offset" : {
                       "type" : "integer"
                   }
             },
             "required": ["name","id","offset"]
        },

        "program_command_jmpdp_t" : {
         "type": "object",
          "properties": {
                "name": {
                    "type" : "string",
                    "enum" : ["jmp_dp"]
                },

               "id" : {
                    "type" : "integer"
                },

               "offset" : {
                    "type" : "integer"
                },

                "duration" : {
                 "type" : "number",
                 "minimum": 0.0
                }
          },
          "required": ["name", "id", "offset", "duration"]
     },

        "program_command_tx_mode_t" : {
            "type": "object",
             "properties": {
                   "name": {
                       "type" : "string",
                       "enum" : ["tx_mode"]
                   },

                  "flags" : {
                       "type" : "integer",
                       "minimum": 0
                   }
             },
             "required": ["name","flags"]
      },


      "program_t" : {
           "type": "object",
           
           "properties": {
                   "commands": {
                         "type": "array",
                         "items": {
                               "anyOf": [
                                 {"$ref": "#/definitions/program_command_tx_t"},
                                 {"$ref": "#/definitions/program_command_rx_t"},
                                 {"$ref": "#/definitions/program_command_keepalive_t"},
                                 {"$ref": "#/definitions/program_command_rx_msg_t"},
                                 {"$ref": "#/definitions/program_command_tx_msg_t"},
                                 {"$ref": "#/definitions/program_command_gen_t"},
                                 {"$ref": "#/definitions/program_command_delay_t"},
                                 {"$ref": "#/definitions/program_command_delay_rnd_t"},
                                 {"$ref": "#/definitions/program_command_set_val_t"},
                                 {"$ref": "#/definitions/program_command_set_tick_var_t"},
                                 {"$ref": "#/definitions/program_command_jmpnz_t"},
                                 {"$ref": "#/definitions/program_command_jmpdp_t"},
                                 {"$ref": "#/definitions/program_command_tx_mode_t"}
                                 
                                 ]
                             },
                          "minItems": 1
                   }
             },

           "required": ["commands"]    
      },
      
      "program_array_t" : {
               "type": "array",
               "items": {
                    "$ref": "#/definitions/program_t"     
                },
                "minItems": 1
      },

      "tunable_t" : {
        "type": "object",
         "properties": {
               "tos": {
                "type" : "integer"
               },
               "ttl": {
                "type" : "integer"
               },
               "mss": {
                "type" : "integer"
               },
               "initwnd": {
                "type" : "integer"
               },
               "no_delay": {
                "type" : "integer"
               },
               "no_delay_counter": {
                "type" : "integer"
               },
               "delay_ack_msec": {
                "type" : "integer"
               },
               "txbufsize": {
                "type" : "integer"
               },
               "rxbufsize": {
                "type" : "integer"
               }
          }
       },

      "tunable_array_t" : {
        "type": "array",
        "items": {
             "$ref": "#/definitions/tunable_t"
         }
      },

      "server_template_t" : {
        "type": "object",
        "properties": {
                "tunable_index": {
                    "type" : "integer",
                    "minimum" : 0
                },

               "program_index": {
                    "type" : "integer",
                    "minimum" : 0
                },
                "assoc" : {
                    "type" : "array",
                     "items": {
                          "type": "object",
                          "properties": {
                               "port": {
                                   "type" : "integer",
                                   "minimum" : 0
                                 }
                          }, 
                          "required": ["port"]
                     }
                }
        },
        "required": ["program_index","assoc"]
    },

    "client_template_t" : {
        "type": "object",
        "properties": {
                "tunable_index": {
                    "type" : "integer",
                    "minimum" : 0
                },

               "program_index": {
                    "type" : "integer",
                    "minimum" : 0
                },
               "port": {
                    "type" : "integer",
                    "minimum": 0
                },
               
               "cps": {
                    "type" : "number",
                    "minimum" : 0.5
                },
               "limit": {
                    "type" : "integer",
                    "minimum": 0
                }
        },
        "required": ["program_index","cps","port"]
    },
    
    "template_t" : {
        "type": "object",
        "properties": {
            "server_template" : {
            "$ref": "#/definitions/server_template_t" 
            },

            "client_template" : {
            "$ref": "#/definitions/client_template_t" 
            }
        },
        "required": ["server_template","client_template"]
    },
   
    "template_array_t" : {
                "type": "array",
                "items": {
                    "$ref": "#/definitions/template_t"
                },
                "minItems": 1
        }

    }
}
`

func validateAppJsonJson(o map[string]interface{}) error {
	bl := o["buf_list"].([]interface{})
	buffers_len := len(bl)
	tunables_len := 0
	if val, ok := o["tunable_list"]; ok {
		tunables_len = len(val.([]interface{}))
	}

	pl := o["program_list"].([]interface{})
	p_len := len(bl)
	for _, o := range pl {
		c1 := o.(map[string]interface{})
		cmds := c1["commands"].([]interface{})
		for _, c := range cmds {
			c2 := c.(map[string]interface{})
			name := c2["name"].(string)
			if name == "tx" || name == "tx_msg" {
				buf_index := c2["buf_index"].(float64)
				if buf_index > float64(buffers_len) {
					err := fmt.Errorf("buffer index is bigger than %v", buffers_len)
					return err
				}
			}
		}
	}

	tl := o["templates"].([]interface{})
	for _, o := range tl {
		c1 := o.(map[string]interface{})
		ct := c1["client_template"].(map[string]interface{})

		if val, ok := ct["tunable_index"]; ok {
			if uint64(val.(float64)) > uint64(tunables_len) {
				err := fmt.Errorf("tunable index is bigger than %v", tunables_len)
				return err
			}
		}

		if val, ok := ct["program_index"]; ok {
			if uint64(val.(float64)) > uint64(p_len) {
				err := fmt.Errorf("program index is bigger than %v", p_len)
				return err
			}
		}

		st := c1["server_template"].(map[string]interface{})

		if val, ok := st["tunable_index"]; ok {
			if uint64(val.(float64)) > uint64(tunables_len) {
				err := fmt.Errorf("tunable index is bigger than %v", tunables_len)
				return err
			}
		}

		if val, ok := st["program_index"]; ok {
			if uint64(val.(float64)) > uint64(p_len) {
				err := fmt.Errorf("program index is bigger than %v", p_len)
				return err
			}
		}

	}

	return nil
}

var schemaLoader gojsonschema.JSONLoader = nil

func IsValidAppSimJson(raw *fastjson.RawMessage, out *map[string]interface{}) error {
	if schemaLoader == nil {
		schemaLoader = gojsonschema.NewStringLoader(schema)
	}
	documentLoader := gojsonschema.NewStringLoader(string(*raw))
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)

	if err != nil {
		return (err)
	}

	if !result.Valid() {
		s := ""
		for _, desc := range result.Errors() {
			s += fmt.Sprintf("- %s\n", desc)
		}
		return fmt.Errorf("%s", s)
	}
	err = json.Unmarshal(*raw, out)
	if err != nil {
		return err
	}

	err = validateAppJsonJson(*out)
	if err != nil {
		return err
	}

	return nil
}
