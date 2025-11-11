package cue

import "strconv"

type CueImportPath string

func (p CueImportPath) String() string {
	return strconv.Quote(string(p))
}
