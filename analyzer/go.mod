// This is a SEPARATE Go module from secmail (../). It is the production
// attachment-analysis worker and is the only part of secmail that imports the
// malengine engine (github.com/YiYuhki/p1), which links libyara via cgo. Keeping
// it in its own module lets `go build ./...` / the Dockerfile for secmail's core
// stay pure-Go (CGO_ENABLED=0) and free of the libyara build dependency.
module github.com/yiyuhki/p2/analyzer

go 1.24.7

require (
	github.com/YiYuhki/p1 v0.0.0
	github.com/redis/go-redis/v9 v9.22.0
)

require (
	github.com/andybalholm/brotli v1.2.2 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/sevenzip v1.6.0 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/glaslos/ssdeep v1.0.0 // indirect
	github.com/glaslos/tlsh v0.4.0 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/hillu/go-yara/v4 v4.3.4 // indirect
	github.com/klauspost/compress v1.19.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.27 // indirect
	github.com/richardlehane/mscfb v1.0.4 // indirect
	github.com/richardlehane/msoleps v1.0.3 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/yeka/zip v0.0.0-20231116150916-03d6312748a9 // indirect
	go.mozilla.org/pkcs7 v0.10.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go4.org v0.0.0-20200411211856-f5505b9728dd // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// malengine lives next to secmail in the workspace.
replace github.com/YiYuhki/p1 => ../../p1
