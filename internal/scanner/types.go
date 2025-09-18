package scanner

type Finding struct {
	Type     string
	Name     string
	Version  string
	Path     string
	File     string
	Reason   string
	Evidence string
}
