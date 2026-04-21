// The idp binary hosts both the HTTP server and the admin CLI.
//
// Subcommands today:
//   idp keys generate    — create a new PENDING signing key
//   idp keys list        — show all signing keys with status
//   idp keys activate    — transition PENDING → ACTIVE (one at a time)
//   idp keys retire      — transition ACTIVE → RETIRED
//
// The HTTP server subcommand will land in a later commit.
//
// Env vars consumed by every subcommand:
//   DATABASE_URL                      required for `keys`
//   JWT_SIGNING_KEY_ENCRYPTION_KEY    required for `keys`; 64 hex chars
package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/tokens"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return usageErr("no subcommand")
	}

	switch args[0] {
	case "keys":
		return runKeys(args[1:])
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		return usageErr(fmt.Sprintf("unknown subcommand %q", args[0]))
	}
}

func runKeys(args []string) error {
	if len(args) < 1 {
		return usageErr("keys: no subcommand")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, kek, err := openDeps(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	store := tokens.NewKeyStore(pool, kek)

	switch args[0] {
	case "generate":
		k, err := store.Generate(ctx)
		if err != nil {
			return fmt.Errorf("generate: %w", err)
		}
		fmt.Printf("generated PENDING key: kid=%s alg=%s\n", k.KID, k.Alg)
		fmt.Println("next: idp keys activate " + k.KID)
		return nil

	case "list":
		keys, err := store.List(ctx)
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
		if len(keys) == 0 {
			fmt.Println("(no signing keys — run: idp keys generate)")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "KID\tALG\tSTATUS\tAGE(d)\tACTIVATED_AT\tRETIRED_AT")
		for _, k := range keys {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
				k.KID, k.Alg, k.Status(), k.AgeDays(),
				ts(k.ActivatedAt), ts(k.RetiredAt))
		}
		return w.Flush()

	case "activate":
		if len(args) < 2 {
			return usageErr("keys activate: missing <kid>")
		}
		kid := args[1]
		if err := store.Activate(ctx, kid); err != nil {
			return fmt.Errorf("activate %s: %w", kid, err)
		}
		fmt.Printf("activated: %s\n", kid)
		return nil

	case "retire":
		if len(args) < 2 {
			return usageErr("keys retire: missing <kid>")
		}
		kid := args[1]
		if err := store.Retire(ctx, kid); err != nil {
			return fmt.Errorf("retire %s: %w", kid, err)
		}
		fmt.Printf("retired: %s (key still appears in JWKS until dropped; wait access_token_ttl + skew)\n", kid)
		return nil

	default:
		return usageErr(fmt.Sprintf("keys: unknown subcommand %q", args[0]))
	}
}

// openDeps opens the Postgres pool + loads the KEK from env. Shared between
// all `keys` subcommands.
func openDeps(ctx context.Context) (*pgxpool.Pool, tokens.KEK, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, nil, fmt.Errorf("DATABASE_URL not set")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("postgres ping: %w", err)
	}

	hexKEK := os.Getenv("JWT_SIGNING_KEY_ENCRYPTION_KEY")
	if hexKEK == "" {
		pool.Close()
		return nil, nil, fmt.Errorf("JWT_SIGNING_KEY_ENCRYPTION_KEY not set (need 64 hex chars)")
	}
	kek, err := tokens.NewEnvKEKFromHex(hexKEK)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("KEK: %w", err)
	}
	return pool, kek, nil
}

// ts formats a nullable timestamp for the list table.
func ts(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.RFC3339)
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usageErr(msg string) error {
	printUsage()
	return &usageError{msg: msg}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `usage: idp <command> [args]

Subcommands:
  keys generate              create a new PENDING signing key
  keys list                  show all signing keys with status and age
  keys activate <kid>        PENDING -> ACTIVE (at most one active, DB-enforced)
  keys retire <kid>          ACTIVE  -> RETIRED (remains in JWKS until aged out)
  help                       print this message

Env:
  DATABASE_URL                     postgres://... (required)
  JWT_SIGNING_KEY_ENCRYPTION_KEY   32 bytes, hex-encoded (required for 'keys')`)
}
