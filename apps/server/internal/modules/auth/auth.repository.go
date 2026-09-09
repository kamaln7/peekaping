package auth

import (
	"context"
)

type Repository interface {
	Create(ctx context.Context, user *Model) (*Model, error)
	FindByEmail(ctx context.Context, email string) (*Model, error)
	FindByID(ctx context.Context, id string) (*Model, error)
	FindAllCount(ctx context.Context) (int64, error)
	Update(ctx context.Context, id string, entity *UpdateModel) error

	// CreateFirst inserts the bootstrap admin under a fixed primary key, so two
	// concurrent bootstraps collide in the database instead of both succeeding.
	// created == false means an admin already exists.
	CreateFirst(ctx context.Context, user *Model) (created bool, out *Model, err error)
	FindByOIDCSubject(ctx context.Context, subject string) (*Model, error)
	// LinkOIDCSubject binds a subject to a user only while it has none.
	LinkOIDCSubject(ctx context.Context, userID string, subject string) (linked bool, err error)
}
