package domain

// DefaultDataDir is the root directory for obscura state on a bootstrapped server.
const DefaultDataDir = "/etc/obscura"

// DefaultDBPath is the SQLite database location relative to DefaultDataDir.
const DefaultDBPath = DefaultDataDir + "/state.db"

// DefaultSingBoxConfigPath is the generated sing-box configuration path.
const DefaultSingBoxConfigPath = DefaultDataDir + "/sing-box.json"

// DefaultManifestPath is the install manifest used for uninstall tracking.
const DefaultManifestPath = DefaultDataDir + "/manifest.json"
