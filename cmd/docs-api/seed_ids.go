package main

// Deterministic UUIDs for the seeded corpus. The SQL seed (migration
// 0002_seed.sql) writes folders + documents at these IDs; SeedFGA
// references them when writing FGA tuples; tests can paste them into
// curl commands.
//
// Keep this file in sync with migrations/0002_seed.sql by hand. There
// are five docs and three folders — small enough that drift would be
// caught on first run.
var SeedIDs = struct {
	FolderEngineering string
	FolderRunbooks    string
	FolderPublic      string

	DocEngOverview   string
	DocDeployRunbook string
	DocOnCallRunbook string
	DocPublicReadme  string
	DocPrivateNotes  string
}{
	FolderEngineering: "11111111-1111-1111-1111-000000000001",
	FolderRunbooks:    "11111111-1111-1111-1111-000000000002",
	FolderPublic:      "11111111-1111-1111-1111-000000000003",

	DocEngOverview:   "22222222-2222-2222-2222-000000000001",
	DocDeployRunbook: "22222222-2222-2222-2222-000000000002",
	DocOnCallRunbook: "22222222-2222-2222-2222-000000000003",
	DocPublicReadme:  "22222222-2222-2222-2222-000000000004",
	DocPrivateNotes:  "22222222-2222-2222-2222-000000000005",
}
