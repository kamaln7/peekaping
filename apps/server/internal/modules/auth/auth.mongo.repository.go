package auth

import (
	"context"
	"errors"
	"peekaping/internal/config"
	"regexp"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type mongoModel struct {
	ID             primitive.ObjectID `bson:"_id"`
	Email          string             `bson:"email"`
	Password       string             `bson:"password"`
	Active         bool               `bson:"active"`
	TwoFASecret    string             `bson:"twofa_secret"`
	TwoFAStatus    bool               `bson:"twofa_status"`
	TwoFALastToken string             `bson:"twofa_last_token"`
	OIDCSubject    *string            `bson:"oidc_subject,omitempty"`
	CreatedAt      time.Time          `bson:"createdAt"`
	UpdatedAt      time.Time          `bson:"updatedAt"`
}

type mongoUpdateModel struct {
	Email          *string    `bson:"email,omitempty"`
	Password       *string    `bson:"password,omitempty"`
	Active         *bool      `bson:"active,omitempty"`
	TwoFASecret    *string    `bson:"twofa_secret,omitempty"`
	TwoFAStatus    *bool      `bson:"twofa_status,omitempty"`
	TwoFALastToken *string    `bson:"twofa_last_token,omitempty"`
	CreatedAt      *time.Time `bson:"createdAt,omitempty"`
	UpdatedAt      *time.Time `bson:"updatedAt,omitempty"`
}

func toDomainModel(mm *mongoModel) *Model {
	return &Model{
		ID:             mm.ID.Hex(),
		Email:          mm.Email,
		Password:       mm.Password,
		Active:         mm.Active,
		TwoFASecret:    mm.TwoFASecret,
		TwoFAStatus:    mm.TwoFAStatus,
		TwoFALastToken: mm.TwoFALastToken,
		OIDCSubject:    derefString(mm.OIDCSubject),
		CreatedAt:      mm.CreatedAt,
		UpdatedAt:      mm.UpdatedAt,
	}
}

type RepositoryImpl struct {
	client     *mongo.Client
	db         *mongo.Database
	collection *mongo.Collection
}

func NewMongoRepository(client *mongo.Client, cfg *config.Config) Repository {
	db := client.Database(cfg.DBName)
	collection := db.Collection("users")

	// Partial unique index: "one OIDC subject, one account" as a database
	// invariant; documents without the field are excluded.
	_, err := collection.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys:    bson.D{{Key: "oidc_subject", Value: 1}},
		Options: options.Index().SetUnique(true).SetPartialFilterExpression(bson.M{"oidc_subject": bson.M{"$type": "string"}}),
	})
	if err != nil {
		panic("Failed to create index on users collection:" + err.Error())
	}

	return &RepositoryImpl{client, db, collection}
}

func (r *RepositoryImpl) Create(ctx context.Context, user *Model) (*Model, error) {
	mm := &mongoModel{
		ID:             primitive.NewObjectID(),
		Email:          user.Email,
		Password:       user.Password,
		Active:         user.Active,
		TwoFASecret:    user.TwoFASecret,
		TwoFAStatus:    user.TwoFAStatus,
		TwoFALastToken: user.TwoFALastToken,
		OIDCSubject:    nullString(user.OIDCSubject),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	_, err := r.collection.InsertOne(ctx, mm)
	if err != nil {
		return nil, err
	}

	return toDomainModel(mm), nil
}

func (r *RepositoryImpl) FindByEmail(ctx context.Context, email string) (*Model, error) {
	var admin mongoModel
	err := r.collection.FindOne(ctx, bson.M{"email": bson.M{"$regex": "^" + regexp.QuoteMeta(email) + "$", "$options": "i"}}).Decode(&admin)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	return toDomainModel(&admin), nil
}

func (r *RepositoryImpl) FindByID(ctx context.Context, id string) (*Model, error) {
	var entity mongoModel

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"_id": objectID}
	err = r.collection.FindOne(ctx, filter).Decode(&entity)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	return toDomainModel(&entity), nil
}

func (r *RepositoryImpl) Update(ctx context.Context, id string, entity *UpdateModel) error {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	mu := &mongoUpdateModel{
		Email:          entity.Email,
		Password:       entity.Password,
		Active:         entity.Active,
		TwoFASecret:    entity.TwoFASecret,
		TwoFAStatus:    entity.TwoFAStatus,
		TwoFALastToken: entity.TwoFALastToken,
	}

	set := buildSetMapFromUpdateModel(mu)

	// Always set updatedAt to current time
	set["updatedAt"] = time.Now()

	if len(set) == 0 {
		return errors.New("nothing to update")
	}

	filter := bson.M{"_id": objectID}
	update := bson.M{"$set": set}

	_, err = r.collection.UpdateOne(ctx, filter, update)
	return err
}

func (r *RepositoryImpl) FindAllCount(ctx context.Context) (int64, error) {
	count, err := r.collection.CountDocuments(ctx, bson.M{})
	return count, err
}

// buildSetMapFromUpdateModel converts mongoUpdateModel to bson.M for MongoDB updates
func buildSetMapFromUpdateModel(mu *mongoUpdateModel) bson.M {
	set := bson.M{}
	if mu.Email != nil {
		set["email"] = *mu.Email
	}
	if mu.Password != nil {
		set["password"] = *mu.Password
	}
	if mu.Active != nil {
		set["active"] = *mu.Active
	}
	if mu.TwoFASecret != nil {
		set["twofa_secret"] = *mu.TwoFASecret
	}
	if mu.TwoFAStatus != nil {
		set["twofa_status"] = *mu.TwoFAStatus
	}
	if mu.TwoFALastToken != nil {
		set["twofa_last_token"] = *mu.TwoFALastToken
	}
	if mu.CreatedAt != nil {
		set["createdAt"] = *mu.CreatedAt
	}
	if mu.UpdatedAt != nil {
		set["updatedAt"] = *mu.UpdatedAt
	}
	return set
}

// bootstrapUserObjectID is the fixed _id of an admin created by CreateFirst; a
// concurrent second bootstrap fails with E11000 instead of creating a rival admin.
var bootstrapUserObjectID = func() primitive.ObjectID {
	id, err := primitive.ObjectIDFromHex("000000000000000000000001")
	if err != nil {
		panic(err)
	}
	return id
}()

func (r *RepositoryImpl) CreateFirst(ctx context.Context, user *Model) (bool, *Model, error) {
	// Legacy installs have a randomly-generated admin _id, so the fixed key would
	// not collide with it; the count check covers that case (no race: an existing
	// admin is stable).
	count, err := r.FindAllCount(ctx)
	if err != nil {
		return false, nil, err
	}
	if count > 0 {
		return false, nil, nil
	}

	mm := &mongoModel{
		ID:             bootstrapUserObjectID,
		Email:          user.Email,
		Password:       user.Password,
		Active:         user.Active,
		TwoFASecret:    user.TwoFASecret,
		TwoFAStatus:    user.TwoFAStatus,
		TwoFALastToken: user.TwoFALastToken,
		OIDCSubject:    nullString(user.OIDCSubject),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if _, err := r.collection.InsertOne(ctx, mm); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return false, nil, nil
		}
		return false, nil, err
	}
	return true, toDomainModel(mm), nil
}

func (r *RepositoryImpl) FindByOIDCSubject(ctx context.Context, subject string) (*Model, error) {
	if subject == "" {
		return nil, nil
	}
	var entity mongoModel
	err := r.collection.FindOne(ctx, bson.M{"oidc_subject": subject}).Decode(&entity)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	return toDomainModel(&entity), nil
}

func (r *RepositoryImpl) LinkOIDCSubject(ctx context.Context, userID string, subject string) (bool, error) {
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return false, err
	}

	res, err := r.collection.UpdateOne(ctx,
		bson.M{"_id": objectID, "oidc_subject": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"oidc_subject": subject, "updatedAt": time.Now()}},
	)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return false, nil
		}
		return false, err
	}
	return res.ModifiedCount == 1, nil
}
