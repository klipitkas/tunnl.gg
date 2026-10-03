package main

import "github.com/klipitkas/tunnl.gg/pkg/serve"

// Set at build time with -ldflags "-X main.version=... -X main.commit=..."
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	serve.Main(serve.Options{Version: version, Commit: commit})
}
