package service

import (
	"context"

	"github.com/ivan-khludov/obscura/internal/apply"
)

// applyConfig renders and applies sing-box configuration.
func (s *Service) applyConfig(ctx context.Context, dryRun bool) (*apply.Result, error) {
	return s.pipeline.Apply(ctx, dryRun)
}

// rollbackConfig restores the previous sing-box configuration revision.
func (s *Service) rollbackConfig(ctx context.Context) error {
	return s.pipeline.Rollback(ctx)
}
