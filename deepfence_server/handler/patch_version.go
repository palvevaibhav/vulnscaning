package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/deepfence/ThreatMapper/deepfence_server/model"
)

// Handler contains the Neo4j driver (no SQL DB)
type Handler struct {
	Neo4jDriver neo4j.DriverWithContext
}

// CreatePatchVersion - POST /patch-version
func (h *Handler) CreatePatchVersion(w http.ResponseWriter, r *http.Request) {
	var p model.PatchVersion

	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	session := h.Neo4jDriver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx,
			`CREATE (p:PatchVersion {
				patch_id: $patch_id,
				component: $component,
				major_version: $major_version,
				minor_version: $minor_version,
				patch_version: $patch_version,
				pre_release: $pre_release,
				build_metadata: $build_metadata,
				version_string: $version_string,
				patch_number: $patch_number,
				release_date: $release_date,
				status: $status,
				supersedes_id: $supersedes_id,
				release_notes: $release_notes
			}) RETURN p`,
			map[string]any{
				"patch_id":       p.PatchID,
				"component":      p.Component,
				"major_version":  p.MajorVersion,
				"minor_version":  p.MinorVersion,
				"patch_version":  p.PatchVersion,
				"pre_release":    p.PreRelease,
				"build_metadata": p.BuildMetadata,
				"version_string": p.VersionString,
				"patch_number":   p.PatchNumber,
				"release_date":   p.ReleaseDate,
				"status":         p.Status,
				"supersedes_id":  p.SupersedesID,
				"release_notes":  p.ReleaseNotes,
			},
		)
		return nil, err
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Neo4j insert error: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(p)
}

// UpdatePatchVersion - PUT /patch-version/{patch_id}
func (h *Handler) UpdatePatchVersion(w http.ResponseWriter, r *http.Request) {
	patchID := chi.URLParam(r, "patch_id")

	var p model.PatchVersion
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	session := h.Neo4jDriver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx,
			`MATCH (pv:PatchVersion {patch_id: $patch_id})
			 SET pv.status = $status,
			     pv.release_notes = $release_notes
			 RETURN pv`,
			map[string]any{
				"patch_id":      patchID,
				"status":        p.Status,
				"release_notes": p.ReleaseNotes,
			},
		)
		return nil, err
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Neo4j update error: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(p)
}

// ListPatchVersions - GET /patch-version
func (h *Handler) ListPatchVersions(w http.ResponseWriter, r *http.Request) {
	component := r.URL.Query().Get("component")
	status := r.URL.Query().Get("status")

	ctx := context.Background()
	session := h.Neo4jDriver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	query := `MATCH (p:PatchVersion) WHERE 1=1`
	params := map[string]any{}

	if component != "" {
		query += " AND p.component = $component"
		params["component"] = component
	}
	if status != "" {
		query += " AND p.status = $status"
		params["status"] = status
	}
	query += " RETURN p"

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		records, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}

		var patches []model.PatchVersion
		for records.Next(ctx) {
			node := records.Record().Values[0].(neo4j.Node)
			props := node.Props

			patch := model.PatchVersion{
				PatchID:       props["patch_id"].(int64),
				Component:     props["component"].(string),
				VersionString: props["version_string"].(string),
				Status:        props["status"].(string),
			}
			patches = append(patches, patch)
		}
		return patches, nil
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Neo4j read error: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(result)
}
