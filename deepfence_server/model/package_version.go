package model

type PatchVersion struct {
    PatchID       int64     `json:"patch_id"`
    Component     string    `json:"component"`
    MajorVersion  int       `json:"major_version"`
    MinorVersion  int       `json:"minor_version"`
    PatchVersion  int       `json:"patch_version"`
    PreRelease    *string   `json:"pre_release,omitempty"`
    BuildMetadata *string   `json:"build_metadata,omitempty"`
    VersionString string    `json:"version_string"`
    PatchNumber   string    `json:"patch_number"`
    ReleaseDate   time.Time `json:"release_date"`
    Status        string    `json:"status"`
    SupersedesID  *string   `json:"supersedes_id,omitempty"`
    ReleaseNotes  *string   `json:"release_notes,omitempty"`
}
