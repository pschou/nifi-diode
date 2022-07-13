// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
	Package param implements command-line parameter parsing in the GNU style.
	It is different and adds capabilities beyond the standard flag package,
	the only difference being the extra argument to Parse.

	Command line param syntax:
		-f		// single letter flag
		-fg		// two single letter flags together
		--flag	// multiple letter flag
		--flag x  // non-present flags only
		-f x		// non-present flags only
		-fx		// if f is a non-present flag, x is its argument.

	The last three forms are not permitted for boolean flags because the
	meaning of the command
		cmd -f *
	will change if there is a file called 0, false, etc.  There is currently
	no way to turn off a boolean flag.

	Flag parsing stops after the terminator "--", or just before the first
	non-flag argument ("-" is a non-flag argument) if the interspersed
	argument to Parse is false.

TODOs:
- add flag for printing out all the possible flags for ease of tab completion
- parse the _POSIX_OPTION_ORDER environment variable for ignoring the flag forder,
    see https://www.gnu.org/software/libc/manual/html_node/Standard-Environment.html
- add thin space for all the double wide chars for alignment
*/
package params

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/mattn/go-runewidth"
	"io"
	"math"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ErrHelp is the error returned if the -help or -h flag is invoked
// but no such flag is defined.
var ErrHelp = errors.New("help requested")

// Word for default
var Default = "Default: "

// -- Present Value
type presentValue bool

func newPresentValue(p *bool) *presentValue {
	*p = false
	return (*presentValue)(p)
}

func (b *presentValue) Set(s []string) error {
	*b = true
	return nil
}

func (b *presentValue) Get() interface{} { return bool(*b) }

func (b *presentValue) String() string { return fmt.Sprintf("%v", *b) }

func (b *presentValue) IsPresentFlag() bool { return true }

// optional interface to indicate boolean flags that can be
// supplied without "=value" text
type presentFlag interface {
	Value
	IsPresentFlag() bool
}

// -- bool Value
type boolValue bool

func newBoolValue(val bool, p *bool) *boolValue {
	*p = val
	return (*boolValue)(p)
}

func (b *boolValue) Set(s []string) error {
	v, err := strconv.ParseBool(s[0])
	*b = boolValue(v)
	return err
}

func (b *boolValue) Get() interface{} { return bool(*b) }

func (b *boolValue) String() string { return fmt.Sprintf("%v", *b) }

func (b *boolValue) IsBoolFlag() bool { return true }

// optional interface to indicate boolean flags that can be
// supplied without "=value" text
type boolFlag interface {
	Value
	IsBoolFlag() bool
}

// -- int Value
type intValue int

func newIntValue(val int, p *int) *intValue {
	*p = val
	return (*intValue)(p)
}

func (i *intValue) Set(s []string) error {
	v, err := strconv.ParseInt(s[0], 0, 64)
	*i = intValue(v)
	return err
}

func (i *intValue) Get() interface{} { return int(*i) }

func (i *intValue) String() string { return fmt.Sprintf("%v", *i) }

// -- int64 Value
type int64Value int64

func newInt64Value(val int64, p *int64) *int64Value {
	*p = val
	return (*int64Value)(p)
}

func (i *int64Value) Set(s []string) error {
	v, err := strconv.ParseInt(s[0], 0, 64)
	*i = int64Value(v)
	return err
}

func (i *int64Value) Get() interface{} { return int64(*i) }

func (i *int64Value) String() string { return fmt.Sprintf("%v", *i) }

// -- uint Value
type uintValue uint

func newUintValue(val uint, p *uint) *uintValue {
	*p = val
	return (*uintValue)(p)
}

func (i *uintValue) Set(s []string) error {
	v, err := strconv.ParseUint(s[0], 0, 64)
	*i = uintValue(v)
	return err
}

func (i *uintValue) Get() interface{} { return uint(*i) }

func (i *uintValue) String() string { return fmt.Sprintf("%v", *i) }

// -- uint64 Value
type uint64Value uint64

func newUint64Value(val uint64, p *uint64) *uint64Value {
	*p = val
	return (*uint64Value)(p)
}

func (i *uint64Value) Set(s []string) error {
	v, err := strconv.ParseUint(s[0], 0, 64)
	*i = uint64Value(v)
	return err
}

func (i *uint64Value) Get() interface{} { return uint64(*i) }

func (i *uint64Value) String() string { return fmt.Sprintf("%v", *i) }

// -- string Value
type stringValue string

func newStringValue(val string, p *string) *stringValue {
	*p = val
	return (*stringValue)(p)
}

func (s *stringValue) Set(val []string) error {
	*s = stringValue(val[0])
	return nil
}

func (s *stringValue) Get() interface{} { return string(*s) }

func (s *stringValue) String() string { return fmt.Sprintf("%s", *s) }

// -- StringSliceValue Value
type stringSliceValue []string

func newStringSliceValue(val []string, p *([]string)) *stringSliceValue {
	*p = val
	return (*stringSliceValue)(p)
}

func (s *stringSliceValue) Set(val []string) error {
	*s = append(*s, stringSliceValue(val)...)
	return nil
}

func (s *stringSliceValue) Get() interface{} { return ([]string)(*s) }

func (s *stringSliceValue) String() string { return fmt.Sprintf("%q", *s) }

// -- float64 Value
type float64Value float64

func newFloat64Value(val float64, p *float64) *float64Value {
	*p = val
	return (*float64Value)(p)
}

func (f *float64Value) Set(s []string) error {
	v, err := strconv.ParseFloat(s[0], 64)
	*f = float64Value(v)
	return err
}

func (f *float64Value) Get() interface{} { return float64(*f) }

func (f *float64Value) String() string { return fmt.Sprintf("%v", *f) }

// -- time.Duration Value
type durationValue time.Duration

func newDurationValue(val time.Duration, p *time.Duration) *durationValue {
	*p = val
	return (*durationValue)(p)
}

func (d *durationValue) Set(s []string) error {
	v, err := time.ParseDuration(s[0])
	*d = durationValue(v)
	return err
}

func (d *durationValue) Get() interface{} { return time.Duration(*d) }

func (d *durationValue) String() string { return (*time.Duration)(d).String() }

type flagFuncValue func([]string) error

func (f flagFuncValue) Set(s []string) error { return f(s) }

func (f flagFuncValue) String() string { return "" }

// Value is the interface to the dynamic value stored in a flag.
// (The default value is represented as a string.)
type Value interface {
	String() string
	Set([]string) error
}

// Getter is an interface that allows the contents of a Value to be retrieved.
// It wraps the Value interface, rather than being part of it, because it
// appeared after Go 1 and its compatibility rules. All Value types provided
// by this package satisfy the Getter interface.
type Getter interface {
	Value
	Get() interface{}
}

// ErrorHandling defines how to handle flag parsing errors.
type ErrorHandling int

const (
	ContinueOnError ErrorHandling = iota
	ExitOnError
	PanicOnError
)

// A FlagSet represents a set of defined flags.
type FlagSet struct {
	// Usage is the function called when an error occurs while parsing flags.
	// The field is a function (not a method) that may be changed to point to
	// a custom error handler.
	Usage func()

	name             string
	Title            string
	parsed           bool
	actual           []*Flag
	formal           []*Flag
	nameList         []string
	Params           []Param // argument parsers for after flags
	args             []string
	procArgs         []string // arguments being processed (gnu only)
	procFlag         string   // flag being processed (gnu only)
	allowIntersperse bool     // (gnu only)
	exitOnError      bool     // does the program exit if there's an error?
	errorHandling    ErrorHandling
	output           io.Writer // nil means stderr; use out() accessor
	curGrouping      string
	mulock           *sync.Mutex

	// SetUsageIndent tells the DefaultPrinter how many spaces to add to before
	// printing the usage for each flag.  By default this is 0 and determined by
	// the maximum comma seperated name length.
	Indent      int // beginning of line space
	UsageIndent int // usage column position

	UsageSpace int // minimum number of spaces required before usage
	TypeSpace  int // minimum number of spaces required before input type string

	ShowGroupings   bool                     // Show the flags in groups
	GroupingHeaders func(string, int) string // function used to generate headers, like "Options:"

	ShowDefaultVal bool // Display the (Default: "") example

	// FlagKnownAs allows different projects to customise what their flags are
	// known as, e.g. 'flag', 'option', 'item'. All error/log messages
	// will use that name when referring to an individual items/flags in this set.
	// For example, if this value is 'option', the default message 'value for param'
	// will become 'value for option'.
	// Default value is 'flag'.
	FlagKnownAs string
}

// A Flag represents the state of a flag.
type Flag struct {
	Name         []string                      // name as it appears on command line
	Usage        string                        // help message
	Value        Value                         // value as set
	DefValue     string                        // default value
	TypeExpected string                        // helpful hint on what is expected
	ArgsNeeded   int                           // arg count wanted
	Grouping     string                        // organize flags into groups
	Options      func(string, string) []string // function to return possible outcomes for bash completion
}

type Param struct {
	Usage        string                                                  // help message
	Value        Value                                                   // value as set
	DefValue     string                                                  // default value
	TypeExpected string                                                  // helpful hint on what is expected
	Options      []string                                                // Available options for tab-fill
	OptionsFunc  func(flagsSeen []Flag, argsSeen []string) []string      // Get options for bash completion
	Test         func(flagsSeen []Flag, argsSeen []string) (bool, error) // Options
}

// splitOn, reads out a string and returns a slice
func splitOn(str string, c rune, count int) (out []string) {
	var line bytes.Buffer
	for i := 0; i < len(str); {
		r, size := utf8.DecodeRuneInString(str[i:])
		if r == c {
			if line.Len() == 0 {
				continue
			}
			out = append(out, line.String())
			line.Reset()
			if len(out) == count-1 {
				line.WriteString(str[i+size:])
				break
			}
		} else {
			line.WriteRune(r)
		}
		i += size
	}
	if line.Len() > 0 {
		out = append(out, line.String())
	}
	return
}

// sortFlags returns the flags as a slice in lexicographical sorted order.
func sortFlags(flags []*Flag) []*Flag {
	list := make(flagsByName, len(flags))
	copy(list, flags)
	//i := 0
	//for _, f := range flags {
	//	list[i] = f.Name[0]
	//	i++
	//}
	sort.Sort(list)
	//result := make([]*Flag, len(list))
	//for i, name := range list {
	//	result[i] = flags[name]
	//}
	return list
}

// Output returns the destination for usage and error messages. os.Stderr is returned if
// output was not set or was set to nil.
func (f *FlagSet) Output() io.Writer {
	if f.output == nil {
		return os.Stderr
	}
	return f.output
}

// Name returns the name of the flag set.
func (f *FlagSet) Name() string {
	return f.name
}

// ErrorHandling returns the error handling behavior of the flag set.
func (f *FlagSet) ErrorHandling() ErrorHandling {
	return f.errorHandling
}

// SetOutput sets the destination for usage and error messages.
// If output is nil, os.Stderr is used.
func (f *FlagSet) SetOutput(output io.Writer) {
	f.output = output
}

// GroupingSet creates a grouping set for new flags added.  This is helpful if
// there are many flags and they can be organized in smaller groupings.
func GroupingSet(grouping string) {
	CommandLine.curGrouping = grouping
}

// GroupingSet creates a grouping set for new flags added.  This is helpful if
// there are many flags and they can be organized in smaller groupings.
func (f *FlagSet) GroupingSet(grouping string) {
	f.curGrouping = grouping
}

// SetAllowIntersperse tells the parser if flags can be interspersed with other
// arguments.  If AllowIntersperse is set to true, arguments and flags can be
// interspersed, that is flags can follow positional arguments.
//
// Example of true:
//   prog -flag1 input1 input2 -flag2
// Example of false: (default)
//   prog -flag1 -flag2 input1 input2
func (f *FlagSet) SetAllowIntersperse(allowIntersperse bool) {
	f.allowIntersperse = allowIntersperse
}

// SetAllowIntersperse tells the parser if flags can be interspersed with other
// arguments.  If AllowIntersperse is set to true, arguments and flags can be
// interspersed, that is flags can follow positional arguments.
//
// Example of true:
//   prog -flag1 input1 input2 -flag2
// Example of false: (default)
//   prog -flag1 -flag2 input1 input2
func SetAllowIntersperse(allowIntersperse bool) {
	CommandLine.allowIntersperse = allowIntersperse
}

// VisitAll visits the flags in lexicographical order, calling fn for each.
// It visits all flags, even those not set.
func (f *FlagSet) VisitAll(fn func(*Flag)) {
	for _, flag := range sortFlags(f.formal) {
		fn(flag)
	}
}

// VisitAll visits the command-line flags in lexicographical order, calling
// fn for each.  It visits all flags, even those not set.
func VisitAll(fn func(*Flag)) {
	CommandLine.VisitAll(fn)
}

// Visit visits the flags in lexicographical order, calling fn for each.
// It visits only those flags that have been set.
func (f *FlagSet) Visit(fn func(*Flag)) {
	for _, flag := range sortFlags(f.actual) {
		fn(flag)
	}
}

// Visit visits the command-line flags in lexicographical order, calling fn
// for each.  It visits only those flags that have been set.
func Visit(fn func(*Flag)) {
	CommandLine.Visit(fn)
}

// Lookup returns the Flag structure of the named flag, returning nil if none exists.
func (f *FlagSet) Lookup(name string) *Flag {
	if f.mulock == nil {
		f.mulock = new(sync.Mutex)
	}
	f.mulock.Lock()
	defer f.mulock.Unlock()
	for _, flag := range f.formal {
		for _, n := range flag.Name {
			if name == n {
				return flag
			}
		}
	}
	return nil
}

// Lookup returns the Flag structure of the named command-line flag,
// returning nil if none exists.
func Lookup(name string) *Flag {
	return CommandLine.Lookup(name)
}

// Set sets the value of the named flag.
func (f *FlagSet) Set(name string, value []string) error {
	f.mulock.Lock()
	defer f.mulock.Unlock()
	var flag *Flag
	for _, flagTest := range f.formal {
		for _, n := range flagTest.Name {
			if n == name {
				flag = flagTest
			}
		}
	}
	if flag == nil {
		return fmt.Errorf("no such %v -%v", f.FlagKnownAs, name)
	}
	err := flag.Value.Set(value)
	if err != nil {
		return err
	}
	if f.actual == nil {
		f.actual = make([]*Flag, 0)
	}
	f.actual = append(f.actual, flag)
	return nil
}

// Set sets the value of the named command-line flag.
func Set(name string, value []string) error {
	return CommandLine.Set(name, value)
}

/*
// flagsByLength is a slice of flags implementing sort.Interface,
// sorting primarily by the length of the flag, and secondarily
// alphabetically.
type flagsByLength []*Flag

func (f flagsByLength) Less(i, j int) bool {
	s1, s2 := f[i].Name, f[j].Name
	if len(s1) != len(s2) {
		return len(s1) < len(s2)
	}
	return s1 < s2
}
func (f flagsByLength) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}
func (f flagsByLength) Len() int {
	return len(f)
}
*/

// flagsByName is a slice of slices of flags implementing sort.Interface,
// alphabetically sorting by the name of the first flag in each slice.
type flagsByName []*Flag

func (f flagsByName) Less(i, j int) bool {
	var a, b int
	if len(f[i].Name) > 1 && len(f[i].Name[0]) == 1 && len(f[i].Name[1]) > 1 {
		a = 1
	}
	if len(f[j].Name) > 1 && len(f[j].Name[0]) == 1 && len(f[i].Name[1]) > 1 {
		b = 1
	}
	return f[i].Name[a] < f[j].Name[b]
}
func (f flagsByName) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}
func (f flagsByName) Len() int {
	return len(f)
}

/*
func (f *FlagSet) ptrToVal(ptr string) (ret Value) {
	f.VisitAll(func(f *Flag) {
		if fmt.Sprintf("%#v") == ptr {
			ret = f.Value
		}
	})
	return
}
*/

func rlen(s string) int {
	return utf8.RuneCount([]byte(s))
}

// PrintDefaults prints, to standard error unless configured
// otherwise, the default values of all defined flags in the set.
// If there is more than one name for a given flag, the usage information and
// default value from the shortest will be printed (or the least alphabetically
// if there are several equally short flag names).
func (f *FlagSet) PrintDefaults() {
	//var maxLen int
	var haveMultiple, haveSingleChar bool
	// group together all flags for a given value
	var flags [](*Flag)
	var nameAndTypeLen []int
	var groupings []string
	var groupingsCount = map[string]int{}

	f.mulock.Lock()
loop_formals:
	for _, flag := range f.formal {
		for _, grp := range groupings {
			if grp == flag.Grouping {
				groupingsCount[flag.Grouping]++
				continue loop_formals
			}
		}
		groupings = append(groupings, flag.Grouping)
		groupingsCount[flag.Grouping] = 1
	}
	f.mulock.Unlock()

	var avgLen float64
	//var uniqueFlag = make(map[string]interface{})
	f.VisitAll(func(flag *Flag) {
		//if _, ok := uniqueFlag[flag.Name[0]]; !ok {
		//uniqueFlag[flag.Name[0]] = nil
		flags = append(flags, flag)

		// Set boolean if we have multiple flags set
		if len(flag.Name) > 1 {
			haveMultiple = true
		}
		// Check if we have single char flags
		for _, name := range flag.Name {
			if rlen(name) == 1 {
				haveSingleChar = true
			}
		}

		if f.UsageIndent == 0 {
			myLen := 2*(len(flag.Name)-1) + f.UsageSpace + f.Indent
			for _, name := range flag.Name {
				myLen += runewidth.StringWidth(name)
			}

			// Math to determine width needed
			if flag.TypeExpected != "" {
				withTypeLen := myLen + f.TypeSpace + runewidth.StringWidth(flag.TypeExpected)
				nameAndTypeLen = append(nameAndTypeLen, withTypeLen)
				avgLen += float64(withTypeLen)
			} else {
				nameAndTypeLen = append(nameAndTypeLen, myLen)
				avgLen += float64(myLen)
			}
		}
		//}
	})

	var usageIndent int

	if f.UsageIndent == 0 {
		avgLen /= float64(len(nameAndTypeLen))
		var stdDev float64
		for _, l := range nameAndTypeLen {
			stdDev += math.Pow(math.Abs(float64(l)-avgLen), 0.5)
		}
		stdDev = math.Pow(stdDev/float64(len(nameAndTypeLen)), 2)

		usageIndent = int(avgLen + stdDev*1.6)
	} else {
		usageIndent = f.UsageIndent
	}

	//sort.Sort(flags)

	// sort the output flags by shortest name for each group.
	//var byName flagsByName
	//for _, f := range flags {
	//	sort.Sort(f)
	//	byName = append(byName, f)
	//}
	pad := "\n"
	for len(pad) <= usageIndent {
		pad += " "
	}

	var line bytes.Buffer
	for _, grp := range groupings {
		if f.ShowGroupings {
			// Print group headers
			fmt.Fprintln(f.Output(), f.GroupingHeaders(grp, groupingsCount[grp]))
			/*plural := ""
			if groupingsCount[grp] > 1 {
				plural = "s"
			}
			if grp == "" {
				fmt.Fprintf(f.Output(), "Option%s:\n", plural)
			} else {
				fmt.Fprintf(f.Output(), "%s option%s:\n", grp, plural)
			}*/
		}

		for _, fs := range flags {
			if f.ShowGroupings {
				// Skip all flags not assigned to this group
				if fs.Grouping != grp {
					continue
				}
			}

			Names := fs.Name[:]
			if len(Names) > 1 && rlen(Names[0]) > 1 && rlen(Names[1]) == 1 {
				Names[0], Names[1] = Names[1], Names[0]
			}
			line.Reset()
			for j := 0; j < f.Indent; j++ {
				line.WriteString(" ")
			}
			if haveSingleChar && haveMultiple && rlen(Names[0]) > 1 && len(Names) == 1 {
				// Indent if we have multiple and single char flags are found
				line.WriteString("    ")
			}
			for i, n := range Names {
				// Put commas between flags
				if i > 0 {
					line.WriteString(", ")
				}
				line.WriteString(flagWithMinus(n))
			}
			if len(fs.TypeExpected) > 0 {
				// Put space before type
				for j := 0; j < f.TypeSpace; j++ {
					line.WriteString(" ")
				}
				line.WriteString(fs.TypeExpected)
			}
			// Put space before usage
			for j := 0; j < f.UsageSpace; j++ {
				line.WriteString(" ")
			}
			usage := fs.Usage

			for runewidth.StringWidth(line.String()) < usageIndent {
				line.WriteString(" ")
			}

			usage = strings.ReplaceAll(usage, "\n", pad)
			if _, ok := fs.Value.(*presentValue); ok {
				fmt.Fprintf(f.Output(), "%s%s\n", line.Bytes(), usage)
			} else if _, ok := fs.Value.(*stringSliceValue); ok {
				fmt.Fprintf(f.Output(), "%s%s\n", line.Bytes(), usage)
			} else if !f.ShowDefaultVal {
				fmt.Fprintf(f.Output(), "%s%s\n", line.Bytes(), usage)
			} else if _, ok := fs.Value.(*stringValue); ok {
				// put quotes on string values
				format := "%s%s  (%s%q)\n"
				fmt.Fprintf(f.Output(), format, line.Bytes(), usage, Default, fs.DefValue)
			} else if _, ok := fs.Value.(flagFuncValue); ok {
				// put quotes on empty func values
				format := "%s%s  (%s%q)\n"
				fmt.Fprintf(f.Output(), format, line.Bytes(), usage, Default, fs.DefValue)
			} else {
				format := "%s%s  (%s%s)\n"
				fmt.Fprintf(f.Output(), format, line.Bytes(), usage, Default, fs.DefValue)
			}
		}

		if !f.ShowGroupings {
			break
		}
	}
}

// PrintDefaults prints to standard error the default values of all defined command-line flags.
func PrintDefaults() {
	CommandLine.PrintDefaults()
}

// defaultUsage is the default function to print a usage message.
func defaultUsage(f *FlagSet) {
	f.PrintDefaults()
}

// NOTE: Usage is not just defaultUsage(CommandLine)
// because it serves (via godoc flag Usage) as the example
// for how to write your own usage function.

// Usage prints to standard error a usage message documenting all defined command-line flags.
// The function is a variable that may be changed to point to a custom function.
var Usage = func() {
	if len(CommandLine.Title) > 0 {
		fmt.Fprintf(CommandLine.Output(), "%s\n\n", CommandLine.Title)
	}
	post := ""
	if len(CommandLine.Params) > 0 {
		post = "[options...] [args...]"
	} else if len(CommandLine.formal) > 1 {
		post = "[options...]"
	} else {
		post = "[option]"
	}
	fmt.Fprintf(CommandLine.Output(), "Usage: %s %s\n", path.Base(os.Args[0]), post)
	PrintDefaults()
}

// Usage prints to standard error a usage message documenting all defined command-line flags.
// The function is a variable that may be changed to point to a custom function.
var defaultGroupingHeaders = func(name string, count int) string {
	plural := ""
	if count > 1 {
		plural = "s"
	}
	if name == "" {
		return fmt.Sprintf("Option%s:", plural)
	} else {
		return fmt.Sprintf("%s option%s:", name, plural)
	}
}

// NFlag returns the number of flags that have been set.
func (f *FlagSet) NFlag() int { return len(f.actual) }

// NFlag returns the number of command-line flags that have been set.
func NFlag() int { return len(CommandLine.actual) }

// Arg returns the i'th argument.  Arg(0) is the first remaining argument
// after flags have been processed.
func (f *FlagSet) Arg(i int) string {
	if i < 0 || i >= len(f.Params) {
		return ""
	}
	return f.args[i]
}

// Arg returns the i'th command-line argument.  Arg(0) is the first remaining argument
// after flags have been processed.
func Arg(i int) string {
	return CommandLine.Arg(i)
}

// NArg is the number of arguments remaining after flags have been processed.
func (f *FlagSet) NArg() int { return len(f.args) }

// NArg is the number of arguments remaining after flags have been processed.
func NArg() int { return len(CommandLine.args) }

// Args returns the non-flag arguments.
func (f *FlagSet) Args() []string { return f.args }

// Args returns the non-flag command-line arguments.
func Args() []string { return CommandLine.args }

// PresVar defines a present flag with specified name and usage string.
// The return value is the address of a bool variable that stores true if seen.
func (f *FlagSet) PresVar(p *bool, name string, usage string) {
	f.Var(newPresentValue(p), name, usage, "", 0)
}

// PresVar defines a present flag with specified name and usage string.
// The return value is the address of a bool variable that stores true if seen.
func PresVar(p *bool, name string, usage string) {
	CommandLine.Var(newPresentValue(p), name, usage, "", 0)
}

// PresVar defines a present flag with specified name and usage string.
// The return value is the address of a bool variable that stores true if seen.
func (f *FlagSet) Pres(name string, usage string) *bool {
	p := new(bool)
	f.PresVar(p, name, usage)
	return p
}

// Pres defines a present flag with specified name and usage string.
// The return value is the address of a bool variable that stores true if seen.
func Pres(name string, usage string) *bool {
	return CommandLine.Pres(name, usage)
}

// BoolVar defines a bool flag with specified name, default value, and usage string.
// The argument p points to a bool variable in which to store the value of the flag.
func (f *FlagSet) BoolVar(p *bool, name string, value bool, usage string, typeExp string) {
	f.Var(newBoolValue(value, p), name, usage, typeExp, 1)
}

// BoolVar defines a bool flag with specified name, default value, and usage string.
// The argument p points to a bool variable in which to store the value of the flag.
func BoolVar(p *bool, name string, value bool, usage string, typeExp string) {
	CommandLine.Var(newBoolValue(value, p), name, usage, typeExp, 1)
}

// Bool defines a bool flag with specified name, default value, and usage string.
// The return value is the address of a bool variable that stores the value of the flag.
func (f *FlagSet) Bool(name string, value bool, usage string, typeExp string) *bool {
	p := new(bool)
	f.BoolVar(p, name, value, usage, typeExp)
	return p
}

// Bool defines a bool flag with specified name, default value, and usage string.
// The return value is the address of a bool variable that stores the value of the flag.
func Bool(name string, value bool, usage string, typeExp string) *bool {
	return CommandLine.Bool(name, value, usage, typeExp)
}

// IntVar defines an int flag with specified name, default value, and usage string.
// The argument p points to an int variable in which to store the value of the flag.
func (f *FlagSet) IntVar(p *int, name string, value int, usage string, typeExp string) {
	f.Var(newIntValue(value, p), name, usage, typeExp, 1)
}

// IntVar defines an int flag with specified name, default value, and usage string.
// The argument p points to an int variable in which to store the value of the flag.
func IntVar(p *int, name string, value int, usage string, typeExp string) {
	CommandLine.Var(newIntValue(value, p), name, usage, typeExp, 1)
}

// Int defines an int flag with specified name, default value, and usage string.
// The return value is the address of an int variable that stores the value of the flag.
func (f *FlagSet) Int(name string, value int, usage string, typeExp string) *int {
	p := new(int)
	f.IntVar(p, name, value, usage, typeExp)
	return p
}

// Int defines an int flag with specified name, default value, and usage string.
// The return value is the address of an int variable that stores the value of the flag.
func Int(name string, value int, usage string, typeExp string) *int {
	return CommandLine.Int(name, value, usage, typeExp)
}

// Int64Var defines an int64 flag with specified name, default value, and usage string.
// The argument p points to an int64 variable in which to store the value of the flag.
func (f *FlagSet) Int64Var(p *int64, name string, value int64, usage string, typeExp string) {
	f.Var(newInt64Value(value, p), name, usage, typeExp, 1)
}

// Int64Var defines an int64 flag with specified name, default value, and usage string.
// The argument p points to an int64 variable in which to store the value of the flag.
func Int64Var(p *int64, name string, value int64, usage string, typeExp string) {
	CommandLine.Var(newInt64Value(value, p), name, usage, typeExp, 1)
}

// Int64 defines an int64 flag with specified name, default value, and usage string.
// The return value is the address of an int64 variable that stores the value of the flag.
func (f *FlagSet) Int64(name string, value int64, usage string, typeExp string) *int64 {
	p := new(int64)
	f.Int64Var(p, name, value, usage, typeExp)
	return p
}

// Int64 defines an int64 flag with specified name, default value, and usage string.
// The return value is the address of an int64 variable that stores the value of the flag.
func Int64(name string, value int64, usage string, typeExp string) *int64 {
	return CommandLine.Int64(name, value, usage, typeExp)
}

// UintVar defines a uint flag with specified name, default value, and usage string.
// The argument p points to a uint variable in which to store the value of the flag.
func (f *FlagSet) UintVar(p *uint, name string, value uint, usage string, typeExp string) {
	f.Var(newUintValue(value, p), name, usage, typeExp, 1)
}

// UintVar defines a uint flag with specified name, default value, and usage string.
// The argument p points to a uint  variable in which to store the value of the flag.
func UintVar(p *uint, name string, value uint, usage string, typeExp string) {
	CommandLine.Var(newUintValue(value, p), name, usage, typeExp, 1)
}

// Uint defines a uint flag with specified name, default value, and usage string.
// The return value is the address of a uint  variable that stores the value of the flag.
func (f *FlagSet) Uint(name string, value uint, usage string, typeExp string) *uint {
	p := new(uint)
	f.UintVar(p, name, value, usage, typeExp)
	return p
}

// Uint defines a uint flag with specified name, default value, and usage string.
// The return value is the address of a uint  variable that stores the value of the flag.
func Uint(name string, value uint, usage string, typeExp string) *uint {
	return CommandLine.Uint(name, value, usage, typeExp)
}

// Uint64Var defines a uint64 flag with specified name, default value, and usage string.
// The argument p points to a uint64 variable in which to store the value of the flag.
func (f *FlagSet) Uint64Var(p *uint64, name string, value uint64, usage string, typeExp string) {
	f.Var(newUint64Value(value, p), name, usage, typeExp, 1)
}

// Uint64Var defines a uint64 flag with specified name, default value, and usage string.
// The argument p points to a uint64 variable in which to store the value of the flag.
func Uint64Var(p *uint64, name string, value uint64, usage string, typeExp string) {
	CommandLine.Var(newUint64Value(value, p), name, usage, typeExp, 1)
}

// Uint64 defines a uint64 flag with specified name, default value, and usage string.
// The return value is the address of a uint64 variable that stores the value of the flag.
func (f *FlagSet) Uint64(name string, value uint64, usage string, typeExp string) *uint64 {
	p := new(uint64)
	f.Uint64Var(p, name, value, usage, typeExp)
	return p
}

// Uint64 defines a uint64 flag with specified name, default value, and usage string.
// The return value is the address of a uint64 variable that stores the value of the flag.
func Uint64(name string, value uint64, usage string, typeExp string) *uint64 {
	return CommandLine.Uint64(name, value, usage, typeExp)
}

// StringVar defines a string flag with specified name, default value, and usage string.
// The argument p points to a string variable in which to store the value of the flag.
func (f *FlagSet) StringVar(p *string, name string, value string, usage string, typeExp string) {
	f.Var(newStringValue(value, p), name, usage, typeExp, 1)
}

// StringVar defines a string flag with specified name, default value, and usage string.
// The argument p points to a string variable in which to store the value of the flag.
func StringVar(p *string, name string, value string, usage string, typeExp string) {
	CommandLine.Var(newStringValue(value, p), name, usage, typeExp, 1)
}

// String defines a string flag with specified name, default value, and usage string.
// The return value is the address of a string variable that stores the value of the flag.
func (f *FlagSet) String(name string, value string, usage string, typeExp string) *string {
	p := new(string)
	f.StringVar(p, name, value, usage, typeExp)
	return p
}

// String defines a string flag with specified name, default value, and usage string.
// The return value is the address of a string variable that stores the value of the flag.
func String(name string, value string, usage string, typeExp string) *string {
	return CommandLine.String(name, value, usage, typeExp)
}

// StringSliceVar defines a string flag with specified name, default value, and usage string.
// The argument p points to a string variable in which to store the value of the flag.
func (f *FlagSet) StringSliceVar(p *([]string), name string, usage string, typeExp string, perFlag int) {
	if perFlag <= 0 {
		perFlag = -1
	}
	f.Var(newStringSliceValue([]string{}, p), name, usage, typeExp, perFlag)
}

// StringSliceVar defines a string flag with specified name, default value, and usage string.
// The argument p points to a string variable in which to store the value of the flag.
func StringSliceVar(p *([]string), name string, usage string, typeExp string, perFlag int) {
	if perFlag <= 0 {
		perFlag = -1
	}
	CommandLine.Var(newStringSliceValue([]string{}, p), name, usage, typeExp, perFlag)
}

// StringSlice defines a string flag with specified name, default value, and usage string.
// The return value is the address of a string variable that stores the value of the flag.
func (f *FlagSet) StringSlice(name string, usage string, typeExp string, perFlag int) *[]string {
	p := new([]string)
	f.StringSliceVar(p, name, usage, typeExp, perFlag)
	return p
}

// StringSlice defines a string flag with specified name, default value, and usage string.
// The return value is the address of a string variable that stores the value of the flag.
func StringSlice(name string, usage string, typeExp string, perFlag int) *[]string {
	return CommandLine.StringSlice(name, usage, typeExp, perFlag)
}

// Float64Var defines a float64 flag with specified name, default value, and usage string.
// The argument p points to a float64 variable in which to store the value of the flag.
func (f *FlagSet) Float64Var(p *float64, name string, value float64, usage string, typeExp string) {
	f.Var(newFloat64Value(value, p), name, usage, typeExp, 1)
}

// Float64Var defines a float64 flag with specified name, default value, and usage string.
// The argument p points to a float64 variable in which to store the value of the flag.
func Float64Var(p *float64, name string, value float64, usage string, typeExp string) {
	CommandLine.Var(newFloat64Value(value, p), name, usage, typeExp, 1)
}

// Float64 defines a float64 flag with specified name, default value, and usage string.
// The return value is the address of a float64 variable that stores the value of the flag.
func (f *FlagSet) Float64(name string, value float64, usage string, typeExp string) *float64 {
	p := new(float64)
	f.Float64Var(p, name, value, usage, typeExp)
	return p
}

// Float64 defines a float64 flag with specified name, default value, and usage string.
// The return value is the address of a float64 variable that stores the value of the flag.
func Float64(name string, value float64, usage string, typeExp string) *float64 {
	return CommandLine.Float64(name, value, usage, typeExp)
}

// DurationVar defines a time.Duration flag with specified name, default value, and usage string.
// The argument p points to a time.Duration variable in which to store the value of the flag.
func (f *FlagSet) DurationVar(p *time.Duration, name string, value time.Duration, usage string, typeExp string) {
	f.Var(newDurationValue(value, p), name, usage, typeExp, 1)
}

// DurationVar defines a time.Duration flag with specified name, default value, and usage string.
// The argument p points to a time.Duration variable in which to store the value of the flag.
func DurationVar(p *time.Duration, name string, value time.Duration, usage string, typeExp string) {
	CommandLine.Var(newDurationValue(value, p), name, usage, typeExp, 1)
}

// Duration defines a time.Duration flag with specified name, default value, and usage string.
// The return value is the address of a time.Duration variable that stores the value of the flag.
func (f *FlagSet) Duration(name string, value time.Duration, usage string, typeExp string) *time.Duration {
	p := new(time.Duration)
	f.DurationVar(p, name, value, usage, typeExp)
	return p
}

// Duration defines a time.Duration flag with specified name, default value, and usage string.
// The return value is the address of a time.Duration variable that stores the value of the flag.
func Duration(name string, value time.Duration, usage string, typeExp string) *time.Duration {
	return CommandLine.Duration(name, value, usage, typeExp)
}

// FlagFunc defines a flag with the specified name and usage string.
// Each time the flag is seen, fn is called with the value of the flag.
// If fn returns a non-nil error, it will be treated as a flag value parsing error.
func (f *FlagSet) FlagFunc(name, usage string, typeExp string, argsNeeded int, fn func([]string) error) {
	f.Var(flagFuncValue(fn), name, usage, typeExp, argsNeeded)
}

// FlagFunc defines a flag with the specified name and usage string.
// Each time the flag is seen, fn is called with the value of the flag.
// If fn returns a non-nil error, it will be treated as a flag value parsing error.
func FlagFunc(name, usage string, typeExp string, argsNeeded int, fn func([]string) error) {
	CommandLine.FlagFunc(name, usage, typeExp, argsNeeded, fn)
}

// Var defines a flag with the specified name and usage string. The type and
// value of the flag are represented by the first argument, of type Value, which
// typically holds a user-defined implementation of Value. For instance, the
// caller could create a flag that turns a comma-separated string into a slice
// of strings by giving the slice the methods of Value; in particular, Set would
// decompose the comma-separated string into the slice.
func (f *FlagSet) Var(value Value, flagStr string, usage string, typeExp string, args int) {
	names := splitOn(flagStr, ' ', -1)

	// Make sure the single char is second, if there is one
	if len(names) > 1 { // TODO: fix for more than two
		if rlen(names[0]) == 1 && rlen(names[1]) > 1 {
			names[0], names[1] = names[1], names[0]
		}
	}

	// Remember the default value as a string; it won't change.
	flag := &Flag{
		Name:         names,
		Usage:        usage,
		Value:        value,
		DefValue:     value.String(),
		TypeExpected: typeExp,
		ArgsNeeded:   args,
		Grouping:     f.curGrouping,
	}

	// Check if the flag exists already
	for _, name := range names {
		alreadythere := f.Lookup(name)
		if alreadythere != nil {
			fmt.Fprintf(f.Output(), "%s %v redefined: %s\n", f.name, f.FlagKnownAs, name)
			panic(fmt.Sprintf("%v redefinition", f.FlagKnownAs)) // Happens only if flags are declared with identical names
		}
	}

	// Go ahead and add this new flag
	if f.formal == nil {
		f.formal = make([]*Flag, 0)
	}
	f.formal = append(f.formal, flag)
}

// Var defines a flag with the specified name and usage string. The type and
// value of the flag are represented by the first argument, of type Value, which
// typically holds a user-defined implementation of Value. For instance, the
// caller could create a flag that turns a comma-separated string into a slice
// of strings by giving the slice the methods of Value; in particular, Set would
// decompose the comma-separated string into the slice.
func Var(value Value, name string, usage string, typeExp string, argsNeeded int) {
	CommandLine.Var(value, name, usage, typeExp, argsNeeded)
}

// failf prints to standard error a formatted error and usage message and
// returns the error.
func (f *FlagSet) failf(format string, a ...interface{}) error {
	err := fmt.Errorf(format, a...)
	fmt.Fprintln(f.Output(), err)
	f.usage()
	return err
}

// usage calls the Usage method for the flag set, or the usage function if
// the flag set is CommandLine.
func (f *FlagSet) usage() {
	if f.Usage == nil {
		if f == CommandLine {
			Usage()
		} else {
			defaultUsage(f)
		}
	} else {
		f.Usage()
	}
}

func (f *FlagSet) parseOne() (flagName string, long, finished bool, err error) {
	if len(f.procArgs) == 0 {
		finished = true
		return
	}

	// processing previously encountered single-rune flag
	if flag := f.procFlag; len(flag) > 0 {
		_, n := utf8.DecodeRuneInString(flag)
		f.procFlag = flag[n:]
		flagName = flag[0:n]
		return
	}

	a := f.procArgs[0]

	// one non-flag argument
	if a == "-" || a == "" || a[0] != '-' {
		if f.allowIntersperse {
			f.args = append(f.args, a)
			f.procArgs = f.procArgs[1:]
			return
		}
		f.args = append(f.args, f.procArgs...)
		f.procArgs = nil
		finished = true
		return
	}

	// end of flags
	if f.procArgs[0] == "--" {
		f.args = append(f.args, f.procArgs[1:]...)
		f.procArgs = nil
		finished = true
		return
	}

	// long flag signified with "--" prefix
	if a[1] == '-' {
		long = true
		if parts := splitOn(a, '=', 2); len(parts) > 1 {
			flagName = parts[0][2:]
			f.procFlag = parts[1]
			f.procArgs = f.procArgs[1:]
			if flagName == "" {
				err = fmt.Errorf("empty %v in argument %q", f.FlagKnownAs, a)
			}
			return
		}
		flagName = a[2:]
		f.procArgs = f.procArgs[1:]
		return
	}

	// some number of single-rune flags
	a = a[1:]
	_, n := utf8.DecodeRuneInString(a)
	if len(a) > n && a[n] == '=' {
		flagName = a[0:n]
		f.procFlag = a[n+1:]
		f.procArgs = f.procArgs[1:]
		return
	}
	flagName = a[0:n]
	f.procFlag = a[n:]
	f.procArgs = f.procArgs[1:]
	return
}

func contains(a []string, b []string) bool {
	found := false
contains_outer:
	for _, B := range a {
		found = false
		for _, A := range a {
			if A == B {
				found = true
				continue contains_outer
			}
		}
		if !found {
			return false
		}
	}

	return found
}

func flagWithMinus(name string) string {
	if rlen(name) > 1 {
		return "--" + name
	}
	return "-" + name
}

func (f *FlagSet) parseFlagArg(name string, long bool) (finished bool, err error) {
	flag := f.Lookup(name)
	if flag == nil {
		if name == "help" || name == "h" { // special case for nice help message.
			f.usage()
			ErrHelp = errors.New(fmt.Sprintf("%v: %v", f.FlagKnownAs, ErrHelp.Error()))
			return false, ErrHelp
		}
		if name == "get-bash-completion" {
			if contains(os.Environ(),
				[]string{"COMP_TYPE", "COMP_LINE", "COMP_POINT", "COMP_KEY"}) {
				if len(os.Args) >= 3 {
					if len(os.Args[3]) > 0 && strings.HasPrefix("-", os.Args[3]) {
						fmt.Println("--")
					}
					for _, flag := range f.formal {
						for _, name := range flag.Name {
							if len(os.Args[3]) > 0 && strings.HasPrefix(flagWithMinus(name), os.Args[3]) {
								fmt.Println(flagWithMinus(name))
							}
						}
					}
				}
			}
			os.Exit(0)
			//fmt.Fprintf(os.Stderr, "go\nmake\nmy day\n")
			//fmt.Printf("makeme\n")
			fmt.Printf("&&go -- test\nmake -- my\nmy day -- plac3\n")
			fmt.Fprintf(os.Stderr, "%#v\n", os.Args)
			for _, e := range os.Environ() {
				if strings.HasPrefix(e, "COM") {
					pair := strings.SplitN(e, "=", 2)
					fmt.Fprintf(os.Stderr, "  %v=%q\n", pair[0], pair[1])
				}
			}
		}
		// Print --xxx when flag is more than one rune.
		return false, f.failf("%v provided but not defined: %s",
			f.FlagKnownAs, flagWithMinus(name))
	}
	switch flag.ArgsNeeded {
	case 0:
		// Param doesn't need an arg.
		flag.Value.Set([]string{})
		if f.procFlag != "" && long {
			found := f.procFlag
			f.procFlag = ""
			return false, f.failf("%v unwanted argument %q found after: %s",
				f.FlagKnownAs, found, flagWithMinus(name))
		}
	case 1:
		// It must have a value, which might be the next argument.
		var hasValue bool
		var value string
		if f.procFlag != "" {
			// value directly follows flag
			value = f.procFlag
			hasValue = true
			f.procFlag = ""
		}
		if !hasValue && len(f.procArgs) > 0 {
			// value is the next arg
			value, f.procArgs = f.procArgs[0], f.procArgs[1:]
			hasValue = true
		}
		if !hasValue {
			return false, f.failf("%v needs an parameter: %s",
				f.FlagKnownAs, flagWithMinus(name))
		}
		if err := flag.Value.Set([]string{value}); err != nil {
			return false, f.failf("invalid value %q for %v %s: %v",
				value, f.FlagKnownAs, flagWithMinus(name), err)
		}
	case -1:
		// Dynamic set of strings, returned as a slice
		if f.procFlag != "" && long {
			found := f.procFlag
			f.procFlag = ""
			return false, f.failf("%v unwanted argument %q found after: %s",
				f.FlagKnownAs, found, flagWithMinus(name))
		}

		toSet := []string{}
		for len(f.procArgs) > 0 {
			if len(f.procArgs[0]) > 0 && f.procArgs[0][0] != '-' {
				toSet = append(toSet, f.procArgs[0])
				f.procArgs = f.procArgs[1:]
			} else {
				break
			}
		}
		flag.Value.Set(toSet)

	default:
		if f.procFlag != "" {
			return false, f.failf("%v needs more than one parameter: %s",
				f.FlagKnownAs, flagWithMinus(name))
		}
		if len(f.procArgs) < flag.ArgsNeeded {
			return false, f.failf("%v not enough parameters provided: %s",
				f.FlagKnownAs, flagWithMinus(name))
		}
		if err := flag.Value.Set(f.procArgs[:flag.ArgsNeeded]); err != nil {
			return false, f.failf("invalid values %q for %v %s: %v",
				f.procArgs[:flag.ArgsNeeded], f.FlagKnownAs, flagWithMinus(name), err)
		}
	}
	f.mulock.Lock()
	defer f.mulock.Unlock()
	if f.actual == nil {
		f.actual = make([]*Flag, 0)
	}
	f.actual = append(f.actual, flag)
	return
}

// Parse parses flag definitions from the argument list, which should not
// include the command name.  Must be called after all flags in the FlagSet
// are defined and before flags are accessed by the program.
// The return value will be ErrHelp if --help or -h was set but not defined.
// If AllowIntersperse is set, arguments and flags can be interspersed, that
// is flags can follow positional arguments.
func (f *FlagSet) Parse(arguments []string) error {
	f.parsed = true
	f.procArgs = arguments
	f.procFlag = ""
	f.args = nil
	for {
		name, long, finished, err := f.parseOne()
		if !finished {
			if name != "" {
				finished, err = f.parseFlagArg(name, long)
			}
		}
		if err != nil {
			switch f.errorHandling {
			case ContinueOnError:
				return err
			case ExitOnError:
				if err == ErrHelp {
					os.Exit(0)
				}
				os.Exit(2)
			case PanicOnError:
				panic(err)
			}
		}
		if !finished {
			continue
		}
		if err == nil {
			break
		}
	}
	return nil
}

// Parsed reports whether f.Parse has been called.
func (f *FlagSet) Parsed() bool {
	return f.parsed
}

// Parse parses the command-line flags from os.Args[1:].  Must be called
// after all flags are defined and before flags are accessed by the program.
// If AllowIntersperse is set, arguments and flags can be interspersed, that
// is flags can follow positional arguments.
func Parse() {
	// Ignore errors; CommandLine is set for ExitOnError.
	CommandLine.Parse(os.Args[1:])
}

// Parsed returns true if the command-line flags have been parsed.
func Parsed() bool {
	return CommandLine.Parsed()
}

// CommandLine is the default set of command-line flags, parsed from os.Args.
// The top-level functions such as BoolVar, Arg, and so on are wrappers for the
// methods of CommandLine.
var CommandLine = NewFlagSet("", ExitOnError)

func init() {
	// Override generic FlagSet default Usage with call to global Usage.
	// Note: This is not CommandLine.Usage = Usage,
	// because we want any eventual call to use any updated value of Usage,
	// not the value it has when this line is run.
	CommandLine.Usage = commandLineUsage
}

func commandLineUsage() {
	Usage()
}

// NewFlagSet returns a new, empty parameter set with the specified name and
// error handling property.
func NewFlagSet(name string, errorHandling ErrorHandling) *FlagSet {
	return NewFlagSetWithFlagKnownAs(name, errorHandling, "parameter")
}

// NewFlagSetWithFlagKnownAs returns a new, empty parameter set with the specified name and
// error handling property. All error messages and other references to the
// individual params will use aka, for e.g. if aka = 'option', the message will be
// 'value for option' not 'value for param'.
func NewFlagSetWithFlagKnownAs(name string, errorHandling ErrorHandling, aka string) *FlagSet {
	f := &FlagSet{
		Title:           "",
		name:            name,
		errorHandling:   errorHandling,
		FlagKnownAs:     aka,
		UsageSpace:      2,
		TypeSpace:       1,
		ShowDefaultVal:  true,
		mulock:          new(sync.Mutex),
		ShowGroupings:   true,
		GroupingHeaders: defaultGroupingHeaders,
		Indent:          2,
	}
	return f
}

// Init sets the name and error handling property for a parameter set.
// By default, the zero FlagSet uses an empty name and the
// ContinueOnError error handling policy.
func (f *FlagSet) Init(name string, errorHandling ErrorHandling) {
	f.name = name
	f.errorHandling = errorHandling
}
