// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"os"
	"strings"
)

// VerifyControl represents a single verification check.
type VerifyControl struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

// HardenVerifyReport is the full verification report emitted as JSON in
// Result.Messages[0] (as a JSON string) and also returned structured
// so the orchestrator can write it to disk.
type HardenVerifyReport struct {
	Level    string          `json:"level"`
	Controls []VerifyControl `json:"controls"`
	Pass     int             `json:"pass"`
	Fail     int             `json:"fail"`
	Total    int             `json:"total"`
}

// RunHardenVerify reads back system state for each applied hardening layer
// and produces a structured report.
func RunHardenVerify(input StepInput) (*Result, error) {
	level, _ := input["level"].(string)
	result := &Result{OK: true}

	report := &HardenVerifyReport{Level: level}

	// SSH
	report.Controls = append(report.Controls, verifySSH()...)

	if level == "standard" || level == "strict" {
		report.Controls = append(report.Controls, verifySysctl()...)
		report.Controls = append(report.Controls, verifyFail2ban()...)
		report.Controls = append(report.Controls, verifyAuditd()...)
		report.Controls = append(report.Controls, verifyServices(input)...)
		report.Controls = append(report.Controls, verifyMounts()...)
		report.Controls = append(report.Controls, verifyNTP()...)
	}

	if level == "strict" {
		report.Controls = append(report.Controls, verifyK3sCIS()...)
	}

	// Tally
	for _, c := range report.Controls {
		if c.Pass {
			report.Pass++
		} else {
			report.Fail++
			result.OK = false
		}
	}
	report.Total = report.Pass + report.Fail

	// Encode report as a single JSON line in Messages for orchestrator to parse
	reportJSON := encodeVerifyReport(report)
	result.Messages = []string{reportJSON}
	result.Changed = []string{fmt.Sprintf("%d/%d controls passed", report.Pass, report.Total)}

	return result, nil
}

// verifySSH checks effective sshd config via sshd -T.
func verifySSH() []VerifyControl {
	out, err := runCommand("sshd", "-T")
	if err != nil {
		return []VerifyControl{{Name: "ssh:config-readable", Pass: false, Detail: err.Error()}}
	}

	var controls []VerifyControl
	checks := map[string]string{
		"passwordauthentication": "no",
		"permitrootlogin":        "no",
		"usedns":                 "no",
	}
	effective := parseSshdT(out)
	for key, want := range checks {
		got, ok := effective[key]
		pass := ok && strings.EqualFold(got, want)
		detail := fmt.Sprintf("want=%s got=%s", want, got)
		if !ok {
			detail = fmt.Sprintf("want=%s; key not found in sshd -T output", want)
		}
		controls = append(controls, VerifyControl{
			Name:   "ssh:" + key,
			Pass:   pass,
			Detail: detail,
		})
	}
	return controls
}

// parseSshdT parses sshd -T output into a lowercase key→value map.
func parseSshdT(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(parts) == 2 {
			m[strings.ToLower(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

// verifySysctl checks key sysctl values.
func verifySysctl() []VerifyControl {
	checks := map[string]string{
		"kernel.kptr_restrict":               "2",
		"kernel.dmesg_restrict":              "1",
		"net.ipv4.tcp_syncookies":            "1",
		"net.ipv4.conf.all.accept_redirects": "0",
		"fs.protected_hardlinks":             "1",
		"fs.protected_symlinks":              "1",
	}
	var controls []VerifyControl
	for key, want := range checks {
		out, err := runCommand("sysctl", "-n", key)
		pass := err == nil && strings.TrimSpace(out) == want
		detail := fmt.Sprintf("want=%s got=%s", want, strings.TrimSpace(out))
		if err != nil {
			detail = fmt.Sprintf("want=%s; error: %v", want, err)
		}
		controls = append(controls, VerifyControl{Name: "sysctl:" + key, Pass: pass, Detail: detail})
	}
	return controls
}

// verifyFail2ban checks fail2ban is active.
func verifyFail2ban() []VerifyControl {
	out, err := runCommand("systemctl", "is-active", "fail2ban")
	pass := err == nil && strings.TrimSpace(out) == "active"
	return []VerifyControl{{Name: "fail2ban:active", Pass: pass, Detail: strings.TrimSpace(out)}}
}

// verifyAuditd checks auditd is active.
func verifyAuditd() []VerifyControl {
	out, err := runCommand("systemctl", "is-active", "auditd")
	pass := err == nil && strings.TrimSpace(out) == "active"
	return []VerifyControl{{Name: "auditd:active", Pass: pass, Detail: strings.TrimSpace(out)}}
}

// verifyServices checks that specified services are disabled.
func verifyServices(input StepInput) []VerifyControl {
	disableBT := boolVal(boolPtr(input, "disable_bluetooth"), false)
	var controls []VerifyControl
	if disableBT {
		for _, svc := range []string{"bluetooth.service"} {
			out, _ := runCommand("systemctl", "is-enabled", svc)
			state := strings.TrimSpace(out)
			pass := state == "disabled" || state == "masked" || state == "not-found"
			controls = append(controls, VerifyControl{
				Name: "service:" + svc + ":disabled", Pass: pass, Detail: "state=" + state,
			})
		}
	}
	return controls
}

// verifyMounts checks /tmp mount flags.
func verifyMounts() []VerifyControl {
	data, err := os.ReadFile("/proc/self/mounts") // #nosec G304 -- /proc/self/mounts is a safe virtual file
	if err != nil {
		return []VerifyControl{{Name: "mounts:readable", Pass: false, Detail: err.Error()}}
	}
	content := string(data)
	var controls []VerifyControl
	for _, mp := range []string{"/tmp", "/dev/shm"} {
		for _, opt := range []string{"noexec", "nosuid", "nodev"} {
			pass := mountHasOption(content, mp, opt)
			controls = append(controls, VerifyControl{
				Name:   fmt.Sprintf("mount:%s:%s", mp, opt),
				Pass:   pass,
				Detail: fmt.Sprintf("%s has %s=%v", mp, opt, pass),
			})
		}
	}
	return controls
}

// mountHasOption checks if a mount point has a given option in /proc/self/mounts.
func mountHasOption(mounts, mountPoint, opt string) bool {
	for _, line := range strings.Split(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[1] == mountPoint {
			for _, o := range strings.Split(fields[3], ",") {
				if o == opt {
					return true
				}
			}
		}
	}
	return false
}

// verifyNTP checks NTP is synchronized.
func verifyNTP() []VerifyControl {
	out, err := runCommand("timedatectl", "show", "--property=NTP")
	pass := err == nil && strings.Contains(out, "NTP=yes")
	return []VerifyControl{{Name: "ntp:enabled", Pass: pass, Detail: strings.TrimSpace(out)}}
}

// verifyK3sCIS checks k3s CIS config exists.
func verifyK3sCIS() []VerifyControl {
	_, err := os.Stat(k3sAuditPolicyPath)
	pass := err == nil
	detail := "audit-policy-file exists"
	if !pass {
		detail = "audit-policy-file missing: " + k3sAuditPolicyPath
	}
	return []VerifyControl{{Name: "k3s-cis:audit-policy", Pass: pass, Detail: detail}}
}

// encodeVerifyReport produces a JSON representation of the report.
// Uses a simple hand-rolled encoder to avoid importing encoding/json in the agent binary
// (which we want to keep small) — but actually encoding/json is already used in result.go,
// so we just use fmt for a readable one-liner format.
func encodeVerifyReport(r *HardenVerifyReport) string {
	var parts []string
	parts = append(parts, fmt.Sprintf(`"level":%q`, r.Level))
	parts = append(parts, fmt.Sprintf(`"pass":%d`, r.Pass))
	parts = append(parts, fmt.Sprintf(`"fail":%d`, r.Fail))
	parts = append(parts, fmt.Sprintf(`"total":%d`, r.Total))

	var ctrls []string
	for _, c := range r.Controls {
		passStr := "false"
		if c.Pass {
			passStr = "true"
		}
		ctrls = append(ctrls, fmt.Sprintf(`{"name":%q,"pass":%s,"detail":%q}`, c.Name, passStr, c.Detail))
	}
	parts = append(parts, fmt.Sprintf(`"controls":[%s]`, strings.Join(ctrls, ",")))
	return "{" + strings.Join(parts, ",") + "}"
}
