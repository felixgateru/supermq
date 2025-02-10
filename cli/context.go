// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"

	"github.com/spf13/cobra"
	"github.com/pelletier/go-toml"
)


const 
	contextPath string ="./context.toml"


type context struct {
	Name     string `toml:"name"`
	DomainID string `toml:"domain_id"`
	Token    string `toml:"token"`
}

type contextManager struct {
	CurrentContext string             `toml:"current_context"`
	Contexts       map[string]context `toml:"contexts"`
}

func ParseContext()(contextManager, error){
	
	_, err := os.Stat(contextPath)
	switch{
	case os.IsNotExist(err):
		defaultContext := contextManager{
			CurrentContext: "default",
			Contexts: map[string]context{
				"default": {
					Name:     "default",
					DomainID: "",
					Token:   "",
				},
			},
		}
		buf, err := toml.Marshal(defaultContext)
		if err != nil {
			return contextManager{}, err
		}
		if err := os.WriteFile(contextPath, buf, filePermission); err != nil {
			return contextManager{}, err
		}
	case err != nil:
		return contextManager{}, err
	}

	context, err := read()
}

func saveContexts(manager contextManager, filePath string) error {
	data, err := json.Marshal(manager)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

func loadContexts(filePath string) (contextManager, error) {
	manager := contextManager{}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return manager, err
	}

	err = json.Unmarshal(data, &manager)
	if err != nil {
		return manager, err
	}

	return manager, nil
}

var contextCmd = []cobra.Command{
	{
		Use:   "create-context <name> <domainID> <token>",
		Short: "Create a new context",
		Long:  "Create a new context with the given name, domainID and token \n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				cmd.Help()
				return
			}

			manager, err := loadContexts(contextsFilePath)
			if err != nil {
				panic(err)
			}

			manager.contexts[args[0]] = context{name: args[0], domainID: args[1], token: args[2]}
			err = saveContexts(manager, contextsFilePath)
			if err != nil {
				panic(err)
			}
		},
	},
	{
		Use:   "use-context <name>",
		Short: "Use a context",
		Long:  "Use a context with the given name \n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				cmd.Help()
				return
			}

			manager, err := loadContexts(contextsFilePath)
			if err != nil {
				panic(err)
			}

			if _, ok := manager.contexts[args[0]]; !ok {
				panic("context not found")
			}

			manager.currentContext = args[0]
			err = saveContexts(manager, contextsFilePath)
			if err != nil {
				panic(err)
			}
		},
	},
	{
		Use:   "list-contexts",
		Short: "List all contexts",
		Long:  "List all contexts \n",
		Run: func(cmd *cobra.Command, args []string) {
			manager, err := loadContexts(contextsFilePath)
			if err != nil {
				panic(err)
			}

			for name, ctx := range manager.contexts {
				if name == manager.currentContext {
					println(name + " *")
				} else {
					println(name)
				}
			}
		},
	},
}
