package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
)

func certFileName(pubkey string) string {
	keyname := filepath.Base(pubkey)
	ext := filepath.Ext(pubkey)
	return fmt.Sprintf("%s-cert%s", strings.TrimRight(keyname, ext), ext)
}
