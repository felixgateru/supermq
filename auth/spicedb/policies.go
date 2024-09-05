// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package spicedb

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/absmach/magistrala/auth"
	"github.com/absmach/magistrala/pkg/errors"
	repoerr "github.com/absmach/magistrala/pkg/errors/repository"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errInternal = errors.New("spicedb internal error")

type policyAgent struct {
	client           *authzed.ClientWithExperimental
	permissionClient v1.PermissionsServiceClient
	logger           *slog.Logger
}

func NewPolicyAgent(client *authzed.ClientWithExperimental, logger *slog.Logger) auth.PolicyAgent {
	return &policyAgent{
		client:           client,
		permissionClient: client.PermissionsServiceClient,
		logger:           logger,
	}
}

func (pa *policyAgent) CheckPolicy(ctx context.Context, pr auth.PolicyReq) error {
	checkReq := v1.CheckPermissionRequest{
		// FullyConsistent means little caching will be available, which means performance will suffer.
		// Only use if a ZedToken is not available or absolutely latest information is required.
		// If we want to avoid FullyConsistent and to improve the performance of  spicedb, then we need to cache the ZEDTOKEN whenever RELATIONS is created or updated.
		// Instead of using FullyConsistent we need to use Consistency_AtLeastAsFresh, code looks like below one.
		// Consistency: &v1.Consistency{
		// 	Requirement: &v1.Consistency_AtLeastAsFresh{
		// 		AtLeastAsFresh: getRelationTupleZedTokenFromCache() ,
		// 	}
		// },
		// Reference: https://authzed.com/docs/reference/api-consistency
		Consistency: &v1.Consistency{
			Requirement: &v1.Consistency_FullyConsistent{
				FullyConsistent: true,
			},
		},
		Resource:   &v1.ObjectReference{ObjectType: pr.ObjectType, ObjectId: pr.Object},
		Permission: pr.Permission,
		Subject:    &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: pr.SubjectType, ObjectId: pr.Subject}, OptionalRelation: pr.SubjectRelation},
	}

	resp, err := pa.permissionClient.CheckPermission(ctx, &checkReq)
	if err != nil {
		return handleSpicedbError(err)
	}
	if resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
		return nil
	}
	if reason, ok := v1.CheckPermissionResponse_Permissionship_name[int32(resp.Permissionship)]; ok {
		return errors.Wrap(svcerr.ErrAuthorization, errors.New(reason))
	}
	return svcerr.ErrAuthorization
}

func (pa *policyAgent) Watch(ctx context.Context, continueToken string) {
	stream, err := pa.client.WatchServiceClient.Watch(ctx, &v1.WatchRequest{
		OptionalObjectTypes: []string{},
		OptionalStartCursor: &v1.ZedToken{Token: continueToken},
	})
	if err != nil {
		pa.logger.Error(fmt.Sprintf("got error while watching: %s", err.Error()))
	}
	for {
		watchResp, err := stream.Recv()
		switch err {
		case nil:
			pa.publishToStream(watchResp)
		case io.EOF:
			pa.logger.Info("got EOF while watch streaming")
			return
		default:
			pa.logger.Error(fmt.Sprintf("got error while watch streaming : %s", err.Error()))
			return
		}
	}
}

func (pa *policyAgent) publishToStream(resp *v1.WatchResponse) {
	pa.logger.Info(fmt.Sprintf("Publish next token %s", resp.ChangesThrough.Token))

	for _, update := range resp.Updates {
		operation := v1.RelationshipUpdate_Operation_name[int32(update.Operation)]
		objectType := update.Relationship.Resource.ObjectType
		objectID := update.Relationship.Resource.ObjectId
		relation := update.Relationship.Relation
		subjectType := update.Relationship.Subject.Object.ObjectType
		subjectRelation := update.Relationship.Subject.OptionalRelation
		subjectID := update.Relationship.Subject.Object.ObjectId

		pa.logger.Info(fmt.Sprintf(`
		Operation : %s	object_type: %s		object_id: %s 	relation: %s 	subject_type: %s 	subject_relation: %s	subject_id: %s
		`, operation, objectType, objectID, relation, subjectType, subjectRelation, subjectID))
	}
}

func handleSpicedbError(err error) error {
	if st, ok := status.FromError(err); ok {
		return convertGRPCStatusToError(st)
	}
	return err
}

func convertGRPCStatusToError(st *status.Status) error {
	switch st.Code() {
	case codes.NotFound:
		return errors.Wrap(repoerr.ErrNotFound, errors.New(st.Message()))
	case codes.InvalidArgument:
		return errors.Wrap(errors.ErrMalformedEntity, errors.New(st.Message()))
	case codes.AlreadyExists:
		return errors.Wrap(repoerr.ErrConflict, errors.New(st.Message()))
	case codes.Unauthenticated:
		return errors.Wrap(svcerr.ErrAuthentication, errors.New(st.Message()))
	case codes.Internal:
		return errors.Wrap(errInternal, errors.New(st.Message()))
	case codes.OK:
		if msg := st.Message(); msg != "" {
			return errors.Wrap(errors.ErrUnidentified, errors.New(msg))
		}
		return nil
	case codes.FailedPrecondition:
		return errors.Wrap(errors.ErrMalformedEntity, errors.New(st.Message()))
	case codes.PermissionDenied:
		return errors.Wrap(svcerr.ErrAuthorization, errors.New(st.Message()))
	default:
		return errors.Wrap(fmt.Errorf("unexpected gRPC status: %s (status code:%v)", st.Code().String(), st.Code()), errors.New(st.Message()))
	}
}
