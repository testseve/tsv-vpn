package tunnel

import "os"

func readFile(path string) (string, error) {
	contents, err := os.ReadFile(path)
	return string(contents), err
}

func readLink(path string) (string, error) { return os.Readlink(path) }
