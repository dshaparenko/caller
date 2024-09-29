package processor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	tools "github.com/devopsext/sre/tools"
)

type FunctionCallRequest struct {
	FunctionName string                 `json:"function_name"`
	Params       map[string]interface{} `json:"params"`
}

type FunctionCallResponse struct {
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type RunProcessorOptions struct {
	// Add any configuration options here
	// For example:
	// MaxConcurrentCalls int
	// Timeout            time.Duration
}

type RunProcessor struct {
	options RunProcessorOptions
	// Add any other necessary fields here
	// For example:
	// logger  common.Logger
	// metrics common.Metrics
}

func (p *RunProcessor) HandleHttpRequest(w http.ResponseWriter, r *http.Request) error {
	var request FunctionCallRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not decode request: %v", err), http.StatusBadRequest)
		return err
	}

	result, err := p.callFunction(request.FunctionName, request.Params)

	response := FunctionCallResponse{}
	if err != nil {
		response.Error = err.Error()
	} else {
		response.Result = result
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

func (p *RunProcessor) callFunction(funcName string, params map[string]interface{}) (interface{}, error) {
	// Get the function from the tool library
	f := reflect.ValueOf(tools.GetFunction(funcName))
	if !f.IsValid() {
		return nil, fmt.Errorf("function %s not found", funcName)
	}

	// Get the function type
	fType := f.Type()

	// Prepare the parameters
	in := make([]reflect.Value, fType.NumIn())
	for i := 0; i < fType.NumIn(); i++ {
		paramName := fType.In(i).Name()
		paramValue, ok := params[paramName]
		if !ok {
			return nil, fmt.Errorf("missing parameter: %s", paramName)
		}
		in[i] = reflect.ValueOf(paramValue)
	}

	// Call the function
	result := f.Call(in)

	// Check for errors (assuming the last return value is an error, if any)
	if len(result) > 0 && !result[len(result)-1].IsNil() {
		return nil, result[len(result)-1].Interface().(error)
	}

	// Return the result (assuming the first return value is the actual result)
	if len(result) > 0 {
		return result[0].Interface(), nil
	}

	return nil, nil
}

func NewRunProcessor(options RunProcessorOptions) *RunProcessor {
	return &RunProcessor{
		options: options,
		// Initialize other fields here
	}
}

func RunProcessorType() string {
	return "Run"
}

func (p *RunProcessor) Type() string {
	return RunProcessorType()
}
