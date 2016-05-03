package main

import (
	"os"
	"time"

	"github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "nozzle"
	app.HelpName = "nozzle"
	app.Usage = "do not look away, while the nozzle is engaging ..."
	app.Version = "1.0.0"
	app.Flags = []cli.Flag{
		cli.StringFlag{Name: "interface, i", Value: "", Usage: "Interface to get packets from"},
		cli.StringFlag{Name: "filename, r", Value: "", Usage: "Filename to read from"},
		cli.StringFlag{Name: "filter, f", Value: "tcp or udp", Usage: "BPF filter for pcap"},
		cli.DurationFlag{Name: "t", Value: time.Minute, Usage: "Flush interval"},
	}
	app.Action = func(c *cli.Context) {
		if c.String("interface") == "" && c.String("filename") == "" {
			cli.ShowCommandHelp(c, c.Command.Name)
			os.Exit(0)
		}
		s := NewSniffer(&Config{
			filename:      c.String("filename"),
			filter:        c.String("filter"),
			iface:         c.String("interface"),
			flushInterval: c.Duration("t"),
		})
		s.Run()
	}
	app.Run(os.Args)

}
