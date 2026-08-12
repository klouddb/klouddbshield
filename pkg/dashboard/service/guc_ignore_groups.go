package service

import (
	"context"
	"fmt"
	"strings"
)

// GucDriftQuery runs fleet drift with optional group and host filters.
func (s *Service) GucDriftQuery(ctx context.Context, groupID, targetID string) (*GucDriftResponse, error) {
	return s.gucDriftFromSnapshotsQuery(ctx, gucDriftQuery{
		GroupID:  strings.TrimSpace(groupID),
		TargetID: strings.TrimSpace(targetID),
	})
}

// ListGucIgnores returns persisted ignore entries.
func (s *Service) ListGucIgnores(ctx context.Context) (*GucIgnoresResponse, error) {
	if s.Repo == nil {
		return &GucIgnoresResponse{Ignores: []GucIgnoreEntryDTO{}}, nil
	}
	list, err := s.Repo.ListGucIgnores(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]GucIgnoreEntryDTO, 0, len(list))
	for _, e := range list {
		out = append(out, GucIgnoreEntryDTO{
			Scope:       e.Scope,
			TargetID:    e.TargetID,
			InstanceKey: e.InstanceKey,
			Guc:         e.GucName,
			IgnoredAt:   e.IgnoredAt,
		})
	}
	return &GucIgnoresResponse{Ignores: out}, nil
}

// SetGucIgnore adds or removes a host/GUC ignore.
func (s *Service) SetGucIgnore(ctx context.Context, scope, targetID, gucName string, ignore bool) error {
	if s.Repo == nil {
		return fmt.Errorf("database not configured")
	}
	scope = strings.TrimSpace(strings.ToLower(scope))
	targetID = strings.TrimSpace(targetID)
	gucName = strings.TrimSpace(gucName)
	if targetID == "" {
		return fmt.Errorf("target_id is required")
	}
	if ignore {
		return s.Repo.UpsertGucIgnore(ctx, scope, targetID, gucName)
	}
	return s.Repo.DeleteGucIgnore(ctx, scope, targetID, gucName)
}

// ListGucServerGroups returns all server groups with baseline summaries.
func (s *Service) ListGucServerGroups(ctx context.Context) (*GucServerGroupsResponse, error) {
	if s.Repo == nil {
		return &GucServerGroupsResponse{Groups: []GucServerGroupDTO{}}, nil
	}
	list, err := s.Repo.ListGucServerGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]GucServerGroupDTO, 0, len(list))
	for _, g := range list {
		dto := GucServerGroupDTO{
			ID:          g.ID,
			Name:        g.Name,
			Description: g.Description,
			MemberIDs:   g.MemberIDs,
			MemberCount: len(g.MemberIDs),
			UpdatedAt:   g.UpdatedAt,
		}
		if dto.MemberIDs == nil {
			dto.MemberIDs = []string{}
		}
		base, err := s.GucBaselineForGroup(ctx, g.ID)
		if err == nil && base != nil && base.Source != "none" && base.KeyCount > 0 {
			dto.Baseline = base
		}
		out = append(out, dto)
	}
	return &GucServerGroupsResponse{Groups: out}, nil
}

// UpsertGucServerGroup creates or updates a group (name/description).
func (s *Service) UpsertGucServerGroup(ctx context.Context, id, name, description string) (*GucServerGroupDTO, error) {
	if s.Repo == nil {
		return nil, fmt.Errorf("database not configured")
	}
	var baseline map[string]string
	if strings.TrimSpace(id) != "" {
		existing, err := s.Repo.GetGucServerGroup(ctx, id)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			baseline = existing.Baseline
		}
	}
	newID, err := s.Repo.UpsertGucServerGroup(ctx, id, name, description, baseline)
	if err != nil {
		return nil, err
	}
	g, err := s.Repo.GetGucServerGroup(ctx, newID)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, fmt.Errorf("group not found after save")
	}
	dto := &GucServerGroupDTO{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		MemberIDs:   g.MemberIDs,
		MemberCount: len(g.MemberIDs),
		UpdatedAt:   g.UpdatedAt,
	}
	if dto.MemberIDs == nil {
		dto.MemberIDs = []string{}
	}
	return dto, nil
}

// DeleteGucServerGroup removes a group.
func (s *Service) DeleteGucServerGroup(ctx context.Context, id string) error {
	if s.Repo == nil {
		return fmt.Errorf("database not configured")
	}
	return s.Repo.DeleteGucServerGroup(ctx, id)
}

// SetGucServerGroupMembers replaces group membership.
func (s *Service) SetGucServerGroupMembers(ctx context.Context, groupID string, targetIDs []string) error {
	if s.Repo == nil {
		return fmt.Errorf("database not configured")
	}
	return s.Repo.SetGucServerGroupMembers(ctx, groupID, targetIDs)
}

// GetGucServerGroup returns one group DTO.
func (s *Service) GetGucServerGroup(ctx context.Context, id string) (*GucServerGroupDTO, error) {
	if s.Repo == nil {
		return nil, fmt.Errorf("database not configured")
	}
	g, err := s.Repo.GetGucServerGroup(ctx, id)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, nil
	}
	dto := &GucServerGroupDTO{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		MemberIDs:   g.MemberIDs,
		MemberCount: len(g.MemberIDs),
		UpdatedAt:   g.UpdatedAt,
	}
	if dto.MemberIDs == nil {
		dto.MemberIDs = []string{}
	}
	base, err := s.GucBaselineForGroup(ctx, g.ID)
	if err == nil && base != nil && base.Source != "none" && base.KeyCount > 0 {
		dto.Baseline = base
	}
	return dto, nil
}
