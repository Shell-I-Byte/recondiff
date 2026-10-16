package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Shell-I-Byte/recondiff/internal/diff"
)

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("recondiff", flag.ContinueOnError)
	// Never let flag.Parse print attacker-controlled options into CI/terminal logs.
	flags.SetOutput(io.Discard)
	flags.Usage = func() {} // -help handled separately using trusted static text.
	before := flags.String("before", "", "older snapshot JSON")
	after := flags.String("after", "", "newer snapshot JSON")
	scope := flags.String("scope", "", "explicit authorized origins JSON")
	output := flags.String("output", "", "write JSON atomically to this filename (default stdout)")
	authorized := flags.Bool("authorized", false, "acknowledge documented authorization for supplied assets")
	version := flags.Bool("version", false, "print version")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "usage: recondiff --before old.json --after new.json --scope authorized-scope.json --authorized [--output report.json]")
			flags.SetOutput(stderr)
			flags.PrintDefaults() // definitions are trusted static strings, not args
			flags.SetOutput(io.Discard)
			return 0
		}
		fmt.Fprintln(stderr, "recondiff: invalid command-line option")
		return 1
	}
	if *version {
		if err := writeFull(stdout, []byte("recondiff "+diff.Version+"\n")); err != nil {
			fmt.Fprintln(stderr, "version output failed")
			return 1
		}
		return 0
	}
	if *before == "" || *after == "" || *scope == "" || !*authorized || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: recondiff --before old.json --after new.json --scope authorized-scope.json --authorized [--output report.json]")
		return 1
	}
	files := []string{*before, *after, *scope}
	data := make([][]byte, 3)
	for i, name := range files {
		// Open with a nonblocking descriptor on supported Unix platforms so a
		// concurrent regular-file -> FIFO replacement cannot hang during open.
		// The file type is validated *on the opened descriptor*, not a prior
		// pathname stat. Other OSes retain an explicitly documented fallback.
		f, err := openRegularInput(name)
		if err != nil {
			if errors.Is(err, errInputNotRegular) {
				fmt.Fprintf(stderr, "input %d must be an accessible regular file\n", i)
			} else {
				fmt.Fprintf(stderr, "cannot open input %d: %s\n", i, safeDiagnostic(err))
			}
			return 1
		}
		b, e := diff.ReadBounded(f)
		closeErr := f.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			fmt.Fprintf(stderr, "cannot read input %d: %s\n", i, safeDiagnostic(e))
			return 1
		}
		data[i] = b
	}
	result, err := diff.Compare(data[0], data[1], data[2])
	if err != nil {
		fmt.Fprintf(stderr, "recondiff: %s\n", safeDiagnostic(err))
		return 1
	}
	b, err := diff.JSON(result)
	if err != nil {
		fmt.Fprintln(stderr, "cannot serialize report")
		return 1
	}
	if *output == "" {
		if err = writeFull(stdout, b); err != nil {
			fmt.Fprintln(stderr, "cannot write report")
			return 1
		}
	} else {
		if err = checkOutputSeparate(*output, files); err != nil {
			fmt.Fprintf(stderr, "unsafe output destination: %s\n", safeDiagnostic(err))
			return 1
		}
		if err = writeAtomic(*output, b); err != nil {
			fmt.Fprintf(stderr, "cannot write output: %s\n", safeDiagnostic(err))
			return 1
		}
	}
	if len(result.Changes) > 0 {
		return 2
	}
	return 0
}

// safeDiagnostic quotes arbitrary untrusted diagnostic bytes, including filenames
// and decoded JSON tokens. QuoteToASCII escapes newlines, terminal escape codes,
// Unicode direction controls and other non-ASCII text. This is for log safety;
// it is not a universal secret-redaction policy.
func safeDiagnostic(err error) string { return strconv.QuoteToASCII(err.Error()) }

// checkOutputSeparate prevents the CLI from replacing evidence or authorization
// inputs. Comparing file identities catches hard links and path aliases. The
// check protects ordinary local usage, not hostile concurrent filesystem races.
func checkOutputSeparate(output string, inputs []string) error {
	st, err := os.Lstat(output)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return errors.New("output path must not be a symlink")
	}
	for _, input := range inputs {
		inputStat, err := os.Stat(input)
		if err != nil {
			return fmt.Errorf("input identity unavailable: %w", err)
		}
		if os.SameFile(st, inputStat) {
			return errors.New("output destination is an input file")
		}
	}
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// writeFull rejects silent short writes, including writers that violate io.Writer.
func writeFull(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}
