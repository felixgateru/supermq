// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	smqsdk "github.com/absmach/supermq/pkg/sdk"
	"github.com/absmach/supermq/users"
	"github.com/spf13/cobra"
)

var cmdUsers = []cobra.Command{
	{
		Use:   "create <first_name> <last_name> <email> <username> <password> <user_auth_token>",
		Short: "Create user",
		Long: "Create user with provided firstname, lastname, email, username and password. Token is optional\n" +
			"For example:\n" +
			"\tsupermq-cli users create jane doe janedoe@example.com jane_doe 12345678 $USER_AUTH_TOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 5 || len(args) > 6 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			if len(args) == 5 {
				args = append(args, "")
			}

			user := smqsdk.User{
				FirstName: args[0],
				LastName:  args[1],
				Email:     args[2],
				Credentials: smqsdk.Credentials{
					Username: args[3],
					Secret:   args[4],
				},
				Status: users.EnabledStatus.String(),
			}
			user, err := sdk.CreateUser(cmd.Context(), user, args[5])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logJSONCmd(*cmd, user)
		},
	},
	{
		Use:   "get [all | <user_id> ] <user_auth_token>",
		Short: "Get users",
		Long: "Get all users or get user by id. Users can be filtered by name or metadata or status\n" +
			"Usage:\n" +
			"\tsupermq-cli users get all <user_auth_token> - lists all users\n" +
			"\tsupermq-cli users get all <user_auth_token> --offset <offset> --limit <limit> - lists all users with provided offset and limit\n" +
			"\tsupermq-cli users get <user_id> <user_auth_token> - shows user with provided <user_id>\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			metadata, err := convertMetadata(Metadata)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			pageMetadata := smqsdk.PageMetadata{
				Username: Username,
				Identity: Identity,
				Offset:   Offset,
				Limit:    Limit,
				Metadata: metadata,
				Status:   Status,
			}
			if args[0] == all {
				l, err := sdk.Users(cmd.Context(), pageMetadata, args[1])
				if err != nil {
					logErrorCmd(*cmd, err)
					return
				}
				logJSONCmd(*cmd, l)
				return
			}
			u, err := sdk.User(cmd.Context(), args[0], args[1])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logJSONCmd(*cmd, u)
		},
	},
	{
		Use:   "token <username> <password>",
		Short: "Get token",
		Long: "Generate a new token with username and password\n" +
			"For example:\n" +
			"\tsupermq-cli users token jane.doe 12345678\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			loginReq := smqsdk.Login{
				Username: args[0],
				Password: args[1],
			}

			token, err := sdk.CreateToken(cmd.Context(), loginReq)
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logJSONCmd(*cmd, token)
		},
	},

	{
		Use:   "refreshtoken <token>",
		Short: "Get token",
		Long: "Generate new token from refresh token\n" +
			"For example:\n" +
			"\tsupermq-cli users refreshtoken <refresh_token>\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			token, err := sdk.RefreshToken(cmd.Context(), args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logJSONCmd(*cmd, token)
		},
	},
	{
		Use:   "update [<user_id> <JSON_string> | tags <user_id> <tags> | username <user_id> <username> | email <user_id> <email>] <user_auth_token>",
		Short: "Update user",
		Long: "Updates either user name and metadata or user tags or user email\n" +
			"Usage:\n" +
			"\tsupermq-cli users update <user_id> '{\"first_name\":\"new first_name\", \"metadata\":{\"key\": \"value\"}}' $USERTOKEN - updates user first and lastname and metadata\n" +
			"\tsupermq-cli users update tags <user_id> '[\"tag1\", \"tag2\"]' $USERTOKEN - updates user tags\n" +
			"\tsupermq-cli users update username <user_id> newusername $USERTOKEN - updates user name\n" +
			"\tsupermq-cli users update email <user_id> newemail@example.com $USERTOKEN - updates user email\n",

		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 4 && len(args) != 3 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			var user smqsdk.User
			if args[0] == "tags" {
				if err := json.Unmarshal([]byte(args[2]), &user.Tags); err != nil {
					logErrorCmd(*cmd, err)
					return
				}
				user.ID = args[1]
				user, err := sdk.UpdateUserTags(cmd.Context(), user, args[3])
				if err != nil {
					logErrorCmd(*cmd, err)
					return
				}

				logJSONCmd(*cmd, user)
				return
			}

			if args[0] == "email" {
				user.ID = args[1]
				user.Email = args[2]
				user, err := sdk.UpdateUserEmail(cmd.Context(), user, args[3])
				if err != nil {
					logErrorCmd(*cmd, err)
					return
				}
				logJSONCmd(*cmd, user)
				return
			}

			if args[0] == "username" {
				user.ID = args[1]
				user.Credentials.Username = args[2]
				user, err := sdk.UpdateUsername(cmd.Context(), user, args[3])
				if err != nil {
					logErrorCmd(*cmd, err)
					return
				}

				logJSONCmd(*cmd, user)
				return

			}

			if args[0] == "role" {
				user.ID = args[1]
				user.Role = args[2]
				user, err := sdk.UpdateUserRole(cmd.Context(), user, args[3])
				if err != nil {
					logErrorCmd(*cmd, err)
					return
				}

				logJSONCmd(*cmd, user)
				return

			}

			if err := json.Unmarshal([]byte(args[1]), &user); err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			user.ID = args[0]
			user, err := sdk.UpdateUser(cmd.Context(), user, args[2])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logJSONCmd(*cmd, user)
		},
	},
	{
		Use:   "profile <user_auth_token>",
		Short: "Get user profile",
		Long: "Get user profile\n" +
			"Usage:\n" +
			"\tsupermq-cli users profile $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			user, err := sdk.UserProfile(cmd.Context(), args[0])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logJSONCmd(*cmd, user)
		},
	},
	{
		Use:   "resetpasswordrequest <email>",
		Short: "Send reset password request",
		Long: "Send reset password request\n" +
			"Usage:\n" +
			"\tsupermq-cli users resetpasswordrequest example@mail.com\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			if err := sdk.ResetPasswordRequest(cmd.Context(), args[0]); err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logOKCmd(*cmd)
		},
	},
	{
		Use:   "resetpassword <password> <confpass> <password_request_token>",
		Short: "Reset password",
		Long: "Reset password\n" +
			"Usage:\n" +
			"\tsupermq-cli users resetpassword 12345678 12345678 $REQUESTTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			if err := sdk.ResetPassword(cmd.Context(), args[0], args[1], args[2]); err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logOKCmd(*cmd)
		},
	},
	{
		Use:   "password <old_password> <password> <user_auth_token>",
		Short: "Update password",
		Long: "Update password\n" +
			"Usage:\n" +
			"\tsupermq-cli users password old_password new_password $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			user, err := sdk.UpdatePassword(cmd.Context(), args[0], args[1], args[2])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logJSONCmd(*cmd, user)
		},
	},
	{
		Use:   "enable <user_id> <user_auth_token>",
		Short: "Change user status to enabled",
		Long: "Change user status to enabled\n" +
			"Usage:\n" +
			"\tsupermq-cli users enable <user_id> <user_auth_token>\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			user, err := sdk.EnableUser(cmd.Context(), args[0], args[1])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logJSONCmd(*cmd, user)
		},
	},
	{
		Use:   "disable <user_id> <user_auth_token>",
		Short: "Change user status to disabled",
		Long: "Change user status to disabled\n" +
			"Usage:\n" +
			"\tsupermq-cli users disable <user_id> <user_auth_token>\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			user, err := sdk.DisableUser(cmd.Context(), args[0], args[1])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logJSONCmd(*cmd, user)
		},
	},
	{
		Use:   "delete <user_id> <user_auth_token>",
		Short: "Delete user",
		Long: "Delete user by id\n" +
			"Usage:\n" +
			"\tsupermq-cli users delete <user_id> $USERTOKEN - delete user with <user_id>\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}
			if err := sdk.DeleteUser(cmd.Context(), args[0], args[1]); err != nil {
				logErrorCmd(*cmd, err)
				return
			}
			logOKCmd(*cmd)
		},
	},
	{
		Use:   "search <query> <user_auth_token>",
		Short: "Search users",
		Long: "Search users by query\n" +
			"Usage:\n" +
			"\tsupermq-cli users search <query> <user_auth_token>\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsageCmd(*cmd, cmd.Use)
				return
			}

			values, err := url.ParseQuery(args[0])
			if err != nil {
				logErrorCmd(*cmd, fmt.Errorf("failed to parse query: %s", err))
			}

			pm := smqsdk.PageMetadata{
				Offset: Offset,
				Limit:  Limit,
				Name:   values.Get("name"),
				ID:     values.Get("id"),
			}

			if off, err := strconv.Atoi(values.Get("offset")); err == nil {
				pm.Offset = uint64(off)
			}

			if lim, err := strconv.Atoi(values.Get("limit")); err == nil {
				pm.Limit = uint64(lim)
			}

			users, err := sdk.SearchUsers(cmd.Context(), pm, args[1])
			if err != nil {
				logErrorCmd(*cmd, err)
				return
			}

			logJSONCmd(*cmd, users)
		},
	},
}

// NewUsersCmd returns users command.
func NewUsersCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "users [create | get | update | token | password | enable | disable | delete | channels | clients | groups | search]",
		Short: "Users management",
		Long:  `Users management: create accounts and tokens"`,
	}

	for i := range cmdUsers {
		cmd.AddCommand(&cmdUsers[i])
	}

	return &cmd
}
