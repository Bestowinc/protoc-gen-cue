module github.com/Bestowinc/protoc-gen-cue

go 1.26.0

// v1.0.3 was tagged on main and declares the wrong module path (github.com/ornew/protoc-gen-cue).
retract v1.0.3

require (
	cuelang.org/go v0.17.1
	google.golang.org/protobuf v1.36.12
)

require github.com/cockroachdb/apd/v3 v3.2.3 // indirect
