package probe

import "strings"

type systemServices struct{}

var allowedServiceQueries = map[string]struct{}{
	"sunshine":        {},
	"sunshineservice": {},
	"vgc":             {},
	"vgk":             {},
}

func serviceQueryAllowed(name string) bool {
	if name == "" || strings.TrimSpace(name) != name {
		return false
	}
	_, ok := allowedServiceQueries[strings.ToLower(name)]
	return ok
}
