package auth

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
)

type sqlModel struct {
	bun.BaseModel `bun:"table:users,alias:u"`

	ID             string    `bun:"id,pk"`
	Email          string    `bun:"email,unique,notnull"`
	Password       string    `bun:"password,notnull"`
	Active         bool      `bun:"active,notnull,default:true"`
	TwoFASecret    string    `bun:"twofa_secret"`
	TwoFAStatus    bool      `bun:"twofa_status,notnull,default:false"`
	TwoFALastToken string    `bun:"twofa_last_token"`
	OIDCSubject    *string   `bun:"oidc_subject"`
	CreatedAt      time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp"`
	UpdatedAt      time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp"`
}

func toDomainModelFromSQL(sm *sqlModel) *Model {
	return &Model{
		ID:             sm.ID,
		Email:          sm.Email,
		Password:       sm.Password,
		Active:         sm.Active,
		TwoFASecret:    sm.TwoFASecret,
		TwoFAStatus:    sm.TwoFAStatus,
		TwoFALastToken: sm.TwoFALastToken,
		OIDCSubject:    derefString(sm.OIDCSubject),
		CreatedAt:      sm.CreatedAt,
		UpdatedAt:      sm.UpdatedAt,
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// nullString keeps the column NULL for password-only users, so the unique index
// on oidc_subject does not collide on empty strings.
func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func toSQLModel(m *Model) *sqlModel {
	return &sqlModel{
		ID:             m.ID,
		Email:          m.Email,
		Password:       m.Password,
		Active:         m.Active,
		TwoFASecret:    m.TwoFASecret,
		TwoFAStatus:    m.TwoFAStatus,
		TwoFALastToken: m.TwoFALastToken,
		OIDCSubject:    nullString(m.OIDCSubject),
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
	}
}

type SQLRepositoryImpl struct {
	db *bun.DB
}

func NewSQLRepository(db *bun.DB) Repository {
	return &SQLRepositoryImpl{db: db}
}

func (r *SQLRepositoryImpl) Create(ctx context.Context, user *Model) (*Model, error) {
	sm := &sqlModel{
		ID:             uuid.New().String(),
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

	// Let Bun handle ID generation based on the database type
	_, err := r.db.NewInsert().Model(sm).Returning("*").Exec(ctx)
	if err != nil {
		return nil, err
	}

	return toDomainModelFromSQL(sm), nil
}

func (r *SQLRepositoryImpl) FindByEmail(ctx context.Context, email string) (*Model, error) {
	sm := new(sqlModel)
	err := r.db.NewSelect().Model(sm).Where("LOWER(email) = LOWER(?)", email).Scan(ctx)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return toDomainModelFromSQL(sm), nil
}

func (r *SQLRepositoryImpl) FindByID(ctx context.Context, id string) (*Model, error) {
	sm := new(sqlModel)
	err := r.db.NewSelect().Model(sm).Where("id = ?", id).Scan(ctx)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return toDomainModelFromSQL(sm), nil
}

func (r *SQLRepositoryImpl) FindAllCount(ctx context.Context) (int64, error) {
	count, err := r.db.NewSelect().Model((*sqlModel)(nil)).Count(ctx)
	return int64(count), err
}

func (r *SQLRepositoryImpl) Update(ctx context.Context, id string, entity *UpdateModel) error {
	query := r.db.NewUpdate().Model((*sqlModel)(nil)).Where("id = ?", id)

	hasUpdates := false

	if entity.Email != nil {
		query = query.Set("email = ?", *entity.Email)
		hasUpdates = true
	}
	if entity.Password != nil {
		query = query.Set("password = ?", *entity.Password)
		hasUpdates = true
	}
	if entity.Active != nil {
		query = query.Set("active = ?", *entity.Active)
		hasUpdates = true
	}
	if entity.TwoFASecret != nil {
		query = query.Set("twofa_secret = ?", *entity.TwoFASecret)
		hasUpdates = true
	}
	if entity.TwoFAStatus != nil {
		query = query.Set("twofa_status = ?", *entity.TwoFAStatus)
		hasUpdates = true
	}
	if entity.TwoFALastToken != nil {
		query = query.Set("twofa_last_token = ?", *entity.TwoFALastToken)
		hasUpdates = true
	}

	if !hasUpdates {
		return nil
	}

	// Always set updated_at
	query = query.Set("updated_at = ?", time.Now())

	_, err := query.Exec(ctx)
	return err
}

// bootstrapUserID is the fixed primary key of an admin created by CreateFirst.
// Two concurrent bootstraps therefore collide on the PK whatever the isolation
// level: INSERT ... WHERE NOT EXISTS alone is not enough under Read Committed.
const bootstrapUserID = "00000000-0000-0000-0000-000000000001"

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") || // postgres
		strings.Contains(msg, "UNIQUE constraint failed") || // sqlite
		strings.Contains(msg, "Error 1062") || // mysql
		strings.Contains(msg, "duplicate key")
}

func (r *SQLRepositoryImpl) CreateFirst(ctx context.Context, user *Model) (bool, *Model, error) {
	sm := toSQLModel(user)
	sm.ID = bootstrapUserID
	sm.CreatedAt = time.Now()
	sm.UpdatedAt = time.Now()

	// INSERT ... SELECT ... WHERE NOT EXISTS keeps legacy installs (whose admin
	// has a random ID) from gaining a second admin. It is not enough on its own:
	// under Read Committed two concurrent statements both see an empty table. The
	// fixed primary key is what makes the second one fail.
	from := ""
	if r.db.Dialect().Name() == dialect.MySQL {
		from = " FROM DUAL"
	}
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, email, password, active, twofa_secret, twofa_status, twofa_last_token, oidc_subject, created_at, updated_at)
		 SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?`+from+` WHERE NOT EXISTS (SELECT 1 FROM users)`,
		sm.ID, sm.Email, sm.Password, sm.Active, sm.TwoFASecret, sm.TwoFAStatus,
		sm.TwoFALastToken, sm.OIDCSubject, sm.CreatedAt, sm.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return false, nil, nil
		}
		return false, nil, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, nil, err
	}
	if affected == 0 {
		return false, nil, nil
	}
	return true, toDomainModelFromSQL(sm), nil
}

func (r *SQLRepositoryImpl) FindByOIDCSubject(ctx context.Context, subject string) (*Model, error) {
	if subject == "" {
		return nil, nil
	}
	sm := new(sqlModel)
	err := r.db.NewSelect().Model(sm).Where("oidc_subject = ?", subject).Scan(ctx)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return toDomainModelFromSQL(sm), nil
}

func (r *SQLRepositoryImpl) LinkOIDCSubject(ctx context.Context, userID string, subject string) (bool, error) {
	res, err := r.db.NewUpdate().Model((*sqlModel)(nil)).
		Set("oidc_subject = ?", subject).
		Set("updated_at = ?", time.Now()).
		Where("id = ? AND oidc_subject IS NULL", userID).
		Exec(ctx)
	if err != nil {
		if isUniqueViolation(err) {
			return false, nil
		}
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}
