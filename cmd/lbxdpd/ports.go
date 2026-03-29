package main

import "fmt"

const (
	startPort = 1024
	maxPort   = 61024
)

func initPorts(update func(uint16) error) error {
	for p := startPort; p < maxPort; p++ {
		if err := update(uint16(p)); err != nil {
			return fmt.Errorf("init port %d: %w", p, err)
		}
	}
	return nil
}
