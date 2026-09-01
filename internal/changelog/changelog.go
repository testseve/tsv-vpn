// Package changelog reads the markdown changelog that ships in the binary
// into the structure the release notes page renders.
package changelog

import "strings"

type Release struct {
	Version  string
	Date     string
	Notes    []string // prose lines between the version and the first section
	Sections []Section
}

type Section struct {
	Title string
	Items []string
}

// Parse understands the keep-a-changelog shape the repository uses:
// `## <version> - <date>` releases holding `### <title>` sections of `- item`
// bullets, where a bullet may wrap onto indented continuation lines.
func Parse(markdown string) []Release {
	var releases []Release
	for line := range strings.Lines(markdown) {
		line = strings.TrimRight(line, "\n")
		switch {
		case strings.HasPrefix(line, "## "):
			version, date, _ := strings.Cut(strings.TrimSpace(line[3:]), " - ")
			releases = append(releases, Release{Version: strings.TrimSpace(version), Date: strings.TrimSpace(date)})
		case len(releases) == 0:
			continue
		case strings.HasPrefix(line, "### "):
			release := &releases[len(releases)-1]
			release.Sections = append(release.Sections, Section{Title: strings.TrimSpace(line[4:])})
		default:
			release := &releases[len(releases)-1]
			if len(release.Sections) == 0 {
				if text := strings.TrimSpace(line); text != "" {
					release.Notes = append(release.Notes, text)
				}
				continue
			}
			section := &release.Sections[len(release.Sections)-1]
			text := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(text, "- "):
				section.Items = append(section.Items, strings.TrimSpace(text[2:]))
			case text != "" && len(section.Items) > 0:
				section.Items[len(section.Items)-1] += " " + text
			}
		}
	}
	return releases
}
