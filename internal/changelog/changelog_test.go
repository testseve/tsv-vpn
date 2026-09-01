package changelog

import (
	"reflect"
	"testing"

	tsvvpn "tsv-vpn"
)

func TestParse(t *testing.T) {
	got := Parse(`# Changelog

## 2026.1.1.0 - 2026-09-01

### Added

- One thing.
- A bullet that wraps
  onto a second line.

### Fixed

- A bug.

## 2026.1.0.0 - 2026-08-19

The first versioned release.

### Added

- Everything.
`)

	want := []Release{
		{
			Version: "2026.1.1.0", Date: "2026-09-01",
			Sections: []Section{
				{Title: "Added", Items: []string{"One thing.", "A bullet that wraps onto a second line."}},
				{Title: "Fixed", Items: []string{"A bug."}},
			},
		},
		{
			Version: "2026.1.0.0", Date: "2026-08-19",
			Notes:    []string{"The first versioned release."},
			Sections: []Section{{Title: "Added", Items: []string{"Everything."}}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

// Forgetting release notes fails the build rather than shipping a stale page.
func TestShippedChangelogLeadsWithCurrentVersion(t *testing.T) {
	releases := Parse(tsvvpn.Changelog)
	if len(releases) == 0 {
		t.Fatal("no releases parsed from CHANGELOG.md")
	}
	if releases[0].Version != tsvvpn.Version {
		t.Fatalf("changelog leads with %s, binary is %s", releases[0].Version, tsvvpn.Version)
	}
	if releases[0].Date == "" {
		t.Fatalf("release %s has no date", releases[0].Version)
	}
}
