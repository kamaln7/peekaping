package auth

import (
	"peekaping/internal/config"
	"peekaping/internal/modules/shared"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"go.uber.org/dig"
	"go.uber.org/zap"
)

// Boot smoke test: the container must be able to build the auth controller,
// including the OIDC provider, and a bad OIDC config must fail boot.
func TestRegisterDependencies_BuildsController(t *testing.T) {
	build := func(cfg *config.Config) error {
		container := dig.New()
		require.NoError(t, container.Provide(func() *config.Config { return cfg }))
		require.NoError(t, container.Provide(func() *zap.SugaredLogger { return zap.NewNop().Sugar() }))
		require.NoError(t, container.Provide(func() shared.SettingService { return &MockSettingService{} }))
		require.NoError(t, container.Provide(func() *bun.DB { return newOIDCTestDB(t) }))
		RegisterDependencies(container, cfg)
		return container.Invoke(func(*Controller) {})
	}

	base := &config.Config{
		DBType: "sqlite", DBName: ":memory:",
		ClientURL: "https://peekaping.example",
	}
	assert.NoError(t, build(base))

	bad := *base
	bad.OIDCIssuer = "http://op.example.com" // not https, not loopback
	assert.Error(t, build(&bad))
}
