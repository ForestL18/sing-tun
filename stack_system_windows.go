package tun

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/ForestL18/sing-tun/internal/winfw"

	"golang.org/x/sys/windows"
)

func fixWindowsFirewall() error {
	absPath, err := filepath.Abs(os.Args[0])
	if err != nil {
		return err
	}

	tcpRule := winfw.FWRule{
		Name:            "sing-tun TCP (" + absPath + ")",
		ApplicationName: absPath,
		Enabled:         true,
		Protocol:        winfw.NET_FW_IP_PROTOCOL_TCP,
		Direction:       winfw.NET_FW_RULE_DIR_IN,
		Action:          winfw.NET_FW_ACTION_ALLOW,
		Profiles:        winfw.NET_FW_PROFILE2_ALL,
	}
	_, err = winfw.FirewallRuleAddAdvanced(tcpRule)
	if err != nil {
		return err
	}

	udpRule := winfw.FWRule{
		Name:            "sing-tun UDP (" + absPath + ")",
		ApplicationName: absPath,
		Enabled:         true,
		Protocol:        winfw.NET_FW_IP_PROTOCOL_UDP,
		Direction:       winfw.NET_FW_RULE_DIR_IN,
		Action:          winfw.NET_FW_ACTION_ALLOW,
		Profiles:        winfw.NET_FW_PROFILE2_ALL,
	}
	_, err = winfw.FirewallRuleAddAdvanced(udpRule)
	return err
}

func retryableListenError(err error) bool {
	return errors.Is(err, windows.WSAEADDRNOTAVAIL)
}
