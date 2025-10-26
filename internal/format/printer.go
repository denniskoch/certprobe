package format

import (
	"fmt"
	"io"
	"text/tabwriter"
)

type Printer struct {
	tw *tabwriter.Writer
}

func NewPrinter(w io.Writer) *Printer {
	return &Printer{
		tw: tabwriter.NewWriter(w, 0, 8, 2, ' ', 0),
	}
}

func (p *Printer) Field(label string, value any) {
	fmt.Fprintf(p.tw, "%s:\t%v\n", label, value)
}

func (p *Printer) Flush() {
	_ = p.tw.Flush()
}
