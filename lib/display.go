package lib

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Lipgloss styles
var (
	headerStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	activeTabStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Underline(true)
	inactiveTabStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	detailLabel      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("4"))
	footerStyle      = lipgloss.NewStyle().Faint(true)
)

// Tab indices
const (
	tabPeers   = 0
	tabRouters = 1
)

// Message type short names for table columns
var msgShortNames = map[string]string{
	"router_solicitation":            "RS",
	"router_advertisement":           "RA",
	"neighbor_solicitation":          "NS",
	"neighbor_advertisement":         "NA",
	"redirect":                       "Rdr",
	"duplicate_address_request":      "DAR",
	"duplicate_address_confirmation": "DAC",
	"mld_query":                      "MQ",
	"mld_report":                     "MR",
	"mld_done":                       "MD",
}

// Column order for display (NDP types followed by MLD types)
var msgColumnOrder = []string{
	"router_solicitation",
	"router_advertisement",
	"neighbor_solicitation",
	"neighbor_advertisement",
	"redirect",
	"duplicate_address_request",
	"duplicate_address_confirmation",
	"mld_query",
	"mld_report",
	"mld_done",
}

// Well-known IPv6 multicast groups and what they indicate
var knownMulticastGroups = map[string]string{
	"ff02::1":            "All Nodes",
	"ff02::2":            "All Routers",
	"ff02::5":            "OSPFv3",
	"ff02::6":            "OSPFv3 DR",
	"ff02::9":            "RIPng",
	"ff02::a":            "EIGRP",
	"ff02::c":            "SSDP/UPnP",
	"ff02::d":            "PIM",
	"ff02::16":           "MLDv2",
	"ff02::fb":           "mDNS",
	"ff02::1:2":          "DHCPv6",
	"ff02::1:3":          "LLMNR",
	"ff05::1:3":          "DHCP Site",
	"ff02::6a":           "VRRP",
	"ff02::12":           "VRRP",
	"ff02::102":          "HSRPv6",
	"ff02::1:ff00:0/104": "Solicited-Node", // prefix, handled specially
}

// tickMsg drives periodic data refresh
type tickMsg time.Time

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Model is the Bubble Tea model for the NDPeekr TUI.
type Model struct {
	stats   *NDPStats
	window  time.Duration
	refresh time.Duration

	// View state
	activeTab  int    // tabPeers or tabRouters
	activeView string // "table" or "detail"

	// Tables
	peerTable   table.Model
	routerTable table.Model

	// Detail view
	selectedPeer   *PeerSummary
	selectedRouter *RouterInfo

	// Data snapshots
	peers   []PeerSummary
	routers []RouterInfo

	quitting bool
}

// NewModel creates a new Bubble Tea model for the NDPeekr TUI.
func NewModel(stats *NDPStats, window, refresh time.Duration) Model {
	m := Model{
		stats:      stats,
		window:     window,
		refresh:    refresh,
		activeTab:  tabPeers,
		activeView: "table",
	}

	m.peerTable = newPeerTable()
	m.routerTable = newRouterTable()
	m.routerTable.Blur()

	// Load initial data
	m.peers = stats.GetStats()
	m.peerTable.SetRows(peerRows(m.peers))
	m.routers = stats.GetRouters()
	m.routerTable.SetRows(routerRows(m.routers))

	return m
}

// Init starts the tick cycle.
func (m Model) Init() tea.Cmd {
	return tickCmd(m.refresh)
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Reserve lines for header, tab bar, footer, and summary text.
		tableHeight := msg.Height - 10
		if tableHeight < 3 {
			tableHeight = 3
		}
		m.peerTable.SetHeight(tableHeight)
		m.routerTable.SetHeight(tableHeight)
		return m, nil

	case tickMsg:
		m.peers = m.stats.GetStats()
		m.stats.Prune()
		m.peerTable.SetRows(peerRows(m.peers))
		m.routers = m.stats.GetRouters()
		m.routerTable.SetRows(routerRows(m.routers))
		return m, tickCmd(m.refresh)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Quit from anywhere
	if key == "ctrl+c" {
		m.quitting = true
		return m, tea.Quit
	}

	// Detail view: only Esc and q are handled
	if m.activeView == "detail" {
		switch key {
		case "esc":
			m.activeView = "table"
		case "q":
			m.quitting = true
			return m, tea.Quit
		}
		return m, nil
	}

	// Table view key handling
	switch key {
	case "q":
		m.quitting = true
		return m, tea.Quit

	case "tab":
		m.switchTab((m.activeTab + 1) % 2)

	case "shift+tab":
		m.switchTab((m.activeTab + 1) % 2)

	case "enter":
		if m.activeTab == tabPeers {
			row := m.peerTable.SelectedRow()
			if row != nil {
				addr := row[0]
				for i := range m.peers {
					if m.peers[i].Address == addr {
						m.selectedPeer = &m.peers[i]
						m.activeView = "detail"
						break
					}
				}
			}
		} else if m.activeTab == tabRouters {
			row := m.routerTable.SelectedRow()
			if row != nil {
				addr := row[0]
				for i := range m.routers {
					if m.routers[i].Address == addr {
						m.selectedRouter = &m.routers[i]
						m.activeView = "detail"
						break
					}
				}
			}
		}
		return m, nil

	default:
		// Delegate navigation keys to the active table
		var cmd tea.Cmd
		if m.activeTab == tabPeers {
			m.peerTable, cmd = m.peerTable.Update(msg)
		} else {
			m.routerTable, cmd = m.routerTable.Update(msg)
		}
		return m, cmd
	}

	return m, nil
}

func (m *Model) switchTab(tab int) {
	m.activeTab = tab
	if tab == tabPeers {
		m.peerTable.Focus()
		m.routerTable.Blur()
	} else {
		m.peerTable.Blur()
		m.routerTable.Focus()
	}
}

// View renders the TUI.
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render(fmt.Sprintf(
		"NDP/MLD Statistics (window: %s, updated: %s)",
		formatDuration(m.window),
		time.Now().Format("15:04:05"),
	)))
	b.WriteString("\n\n")

	// Tab bar
	b.WriteString(m.renderTabBar())
	b.WriteString("\n\n")

	if m.activeView == "detail" {
		if m.activeTab == tabRouters && m.selectedRouter != nil {
			b.WriteString(m.renderRouterDetail())
		} else {
			b.WriteString(m.renderDetail())
		}
	} else {
		b.WriteString(m.renderTableView())
	}

	// Footer
	b.WriteString("\n")
	if m.activeView == "detail" {
		b.WriteString(footerStyle.Render("Esc: back  q: quit"))
	} else {
		b.WriteString(footerStyle.Render("↑/↓: navigate  Enter: details  Tab: switch view  q: quit"))
	}
	b.WriteString("\n")

	return b.String()
}

func (m Model) renderTabBar() string {
	tabs := []string{"NDP/MLD Peers", "Routers"}
	var parts []string
	for i, name := range tabs {
		if i == m.activeTab {
			parts = append(parts, activeTabStyle.Render("[ "+name+" ]"))
		} else {
			parts = append(parts, inactiveTabStyle.Render("  "+name+"  "))
		}
	}
	return strings.Join(parts, "  ")
}

func (m Model) renderTableView() string {
	var b strings.Builder

	if m.activeTab == tabPeers {
		if len(m.peers) == 0 {
			b.WriteString("No NDP/MLD traffic observed yet...\n")
			return b.String()
		}

		b.WriteString(m.peerTable.View())
		b.WriteString("\n\n")
		b.WriteString(fmt.Sprintf("Total peers: %d\n", len(m.peers)))

		// Multicast group summary
		groupMembers := aggregateMulticastGroups(m.peers)
		if len(groupMembers) > 0 {
			b.WriteString("\n")
			b.WriteString(headerStyle.Render("Multicast Groups:"))
			b.WriteString("\n")
			for _, gm := range groupMembers {
				label := multicastLabel(gm.Group)
				noun := "hosts"
				if gm.Members == 1 {
					noun = "host"
				}
				b.WriteString(fmt.Sprintf("  %-40s %-16s %d %s\n",
					truncate(gm.Group, 40), label, gm.Members, noun))
			}
		}
	} else {
		if len(m.routers) == 0 {
			b.WriteString("No routers observed yet...\n")
		} else {
			b.WriteString(m.routerTable.View())
			b.WriteString("\n\n")
			b.WriteString(fmt.Sprintf("Total routers: %d\n", len(m.routers)))
		}
	}

	return b.String()
}

func (m Model) renderDetail() string {
	if m.selectedPeer == nil {
		return "No peer selected.\n"
	}
	p := m.selectedPeer

	var b strings.Builder

	b.WriteString(headerStyle.Render("Peer Detail: " + p.Address))
	b.WriteString("\n\n")

	// Identity
	mac := p.MAC
	if mac == "" {
		mac = "-"
	}
	hl := "-"
	if p.HopLimit != 0 {
		hl = fmt.Sprintf("%d", p.HopLimit)
	}
	iface := p.Interface
	if iface == "" {
		iface = "-"
	}
	b.WriteString(fmt.Sprintf("  %s  %s\n", detailLabel.Render("MAC:"), mac))
	b.WriteString(fmt.Sprintf("  %s  %s\n", detailLabel.Render("Hop Limit:"), hl))
	b.WriteString(fmt.Sprintf("  %s  %s\n", detailLabel.Render("Interface:"), iface))
	b.WriteString(fmt.Sprintf("  %s  %s\n", detailLabel.Render("First Seen:"), formatTimestamp(p.FirstSeen)))
	b.WriteString(fmt.Sprintf("  %s  %s\n", detailLabel.Render("Last Seen:"), formatTimestamp(p.LastSeen)))

	// Message counts
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s\n", detailLabel.Render("Message Counts:")))
	// NDP row
	b.WriteString("    ")
	for _, kind := range msgColumnOrder[:7] {
		name := msgShortNames[kind]
		count := p.Counts[kind]
		b.WriteString(fmt.Sprintf("%-5s %4d    ", name, count))
	}
	b.WriteString("\n")
	// MLD row
	b.WriteString("    ")
	for _, kind := range msgColumnOrder[7:] {
		name := msgShortNames[kind]
		count := p.Counts[kind]
		b.WriteString(fmt.Sprintf("%-5s %4d    ", name, count))
	}
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("\n  %s  %d\n", detailLabel.Render("Total:"), p.Total))

	// Multicast groups
	if len(p.Groups) > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", detailLabel.Render("Multicast Groups:")))
		for _, group := range p.Groups {
			label := multicastLabel(group)
			if label != "" {
				b.WriteString(fmt.Sprintf("    %-40s %s\n", group, label))
			} else {
				b.WriteString(fmt.Sprintf("    %s\n", group))
			}
		}
	}

	return b.String()
}

// --- Table constructors ---

func newPeerTable() table.Model {
	columns := []table.Column{
		{Title: "IPv6 Address", Width: 40},
		{Title: "MAC", Width: 17},
		{Title: "HL", Width: 3},
		{Title: "Iface", Width: 10},
		{Title: "RS", Width: 4},
		{Title: "RA", Width: 4},
		{Title: "NS", Width: 4},
		{Title: "NA", Width: 4},
		{Title: "Rdr", Width: 4},
		{Title: "DAR", Width: 4},
		{Title: "DAC", Width: 4},
		{Title: "MQ", Width: 4},
		{Title: "MR", Width: 4},
		{Title: "MD", Width: 4},
		{Title: "Total", Width: 5},
		{Title: "First", Width: 8},
		{Title: "Last", Width: 8},
	}

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(20),
		table.WithStyles(s),
	)

	return t
}

func newRouterTable() table.Model {
	columns := []table.Column{
		{Title: "Router Address", Width: 40},
		{Title: "MAC", Width: 17},
		{Title: "Life", Width: 6},
		{Title: "Hop", Width: 3},
		{Title: "M", Width: 1},
		{Title: "O", Width: 1},
		{Title: "Pfx", Width: 3},
		{Title: "MTU", Width: 5},
		{Title: "DNS", Width: 3},
		{Title: "Iface", Width: 10},
		{Title: "Last Seen", Width: 8},
	}

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(false),
		table.WithHeight(20),
		table.WithStyles(s),
	)

	return t
}

// peerRows converts PeerSummary data into table rows.
func peerRows(peers []PeerSummary) []table.Row {
	rows := make([]table.Row, 0, len(peers))
	for _, p := range peers {
		mac := p.MAC
		if mac == "" {
			mac = "-"
		}
		hl := "-"
		if p.HopLimit != 0 {
			hl = fmt.Sprintf("%d", p.HopLimit)
		}
		iface := p.Interface
		if iface == "" {
			iface = "-"
		}
		row := table.Row{
			p.Address,
			mac,
			hl,
			iface,
		}
		for _, kind := range msgColumnOrder {
			row = append(row, fmt.Sprintf("%d", p.Counts[kind]))
		}
		row = append(row,
			fmt.Sprintf("%d", p.Total),
			formatTimestamp(p.FirstSeen),
			formatTimestamp(p.LastSeen),
		)
		rows = append(rows, row)
	}
	return rows
}

// routerRows converts RouterInfo data into table rows.
func routerRows(routers []RouterInfo) []table.Row {
	rows := make([]table.Row, 0, len(routers))
	for _, r := range routers {
		mac := r.MAC
		if mac == "" {
			mac = "-"
		}
		hop := "-"
		if r.HopLimit != 0 {
			hop = fmt.Sprintf("%d", r.HopLimit)
		}
		m := "N"
		if r.Managed {
			m = "Y"
		}
		o := "N"
		if r.Other {
			o = "Y"
		}
		mtu := "-"
		if r.MTU != 0 {
			mtu = fmt.Sprintf("%d", r.MTU)
		}
		iface := r.Interface
		if iface == "" {
			iface = "-"
		}
		rows = append(rows, table.Row{
			r.Address,
			mac,
			formatDuration(r.Lifetime),
			hop,
			m,
			o,
			fmt.Sprintf("%d", len(r.Prefixes)),
			mtu,
			fmt.Sprintf("%d", len(r.RDNSS)),
			iface,
			formatTimestamp(r.LastSeen),
		})
	}
	return rows
}

func (m Model) renderRouterDetail() string {
	r := m.selectedRouter
	if r == nil {
		return "No router selected.\n"
	}

	var b strings.Builder

	b.WriteString(headerStyle.Render("Router Detail: " + r.Address))
	b.WriteString("\n\n")

	// Identity
	mac := r.MAC
	if mac == "" {
		mac = "-"
	}
	hop := "-"
	if r.HopLimit != 0 {
		hop = fmt.Sprintf("%d", r.HopLimit)
	}
	iface := r.Interface
	if iface == "" {
		iface = "-"
	}
	b.WriteString(fmt.Sprintf("  %s  %s\n", detailLabel.Render("MAC:"), mac))
	b.WriteString(fmt.Sprintf("  %s  %s\n", detailLabel.Render("Interface:"), iface))
	b.WriteString(fmt.Sprintf("  %s  %s\n", detailLabel.Render("Hop Limit:"), hop))
	b.WriteString(fmt.Sprintf("  %s  %s\n", detailLabel.Render("First Seen:"), formatTimestamp(r.FirstSeen)))
	b.WriteString(fmt.Sprintf("  %s  %s\n", detailLabel.Render("Last Seen:"), formatTimestamp(r.LastSeen)))

	// Flags and Lifetime
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s\n", detailLabel.Render("Router Advertisement:")))
	b.WriteString(fmt.Sprintf("    Lifetime:      %s\n", formatDuration(r.Lifetime)))
	managed := "No"
	if r.Managed {
		managed = "Yes  (use DHCPv6 for addresses)"
	}
	other := "No"
	if r.Other {
		other = "Yes  (use DHCPv6 for other config)"
	}
	b.WriteString(fmt.Sprintf("    Managed (M):   %s\n", managed))
	b.WriteString(fmt.Sprintf("    Other (O):     %s\n", other))
	if r.MTU != 0 {
		b.WriteString(fmt.Sprintf("    MTU:           %d\n", r.MTU))
	}

	// Prefixes
	if len(r.Prefixes) > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", detailLabel.Render("Prefixes:")))
		b.WriteString(fmt.Sprintf("    %-40s  %-8s  %-8s  %s  %s\n",
			"Prefix", "Valid", "Pref", "L", "A"))
		for _, p := range r.Prefixes {
			onLink := "N"
			if p.OnLink {
				onLink = "Y"
			}
			auto := "N"
			if p.Autonomous {
				auto = "Y"
			}
			b.WriteString(fmt.Sprintf("    %-40s  %-8s  %-8s  %s  %s\n",
				p.Prefix,
				formatDuration(p.ValidLifetime),
				formatDuration(p.PreferredLife),
				onLink,
				auto,
			))
		}
	}

	// DNS Servers
	if len(r.RDNSS) > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", detailLabel.Render("DNS Servers (RDNSS):")))
		for _, dns := range r.RDNSS {
			b.WriteString(fmt.Sprintf("    %s\n", dns))
		}
	}

	// Routes
	if len(r.Routes) > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", detailLabel.Render("Routes:")))
		b.WriteString(fmt.Sprintf("    %-40s  %-8s  %s\n", "Prefix", "Lifetime", "Pref"))
		for _, rt := range r.Routes {
			pref := "med"
			switch rt.Preference {
			case 1:
				pref = "high"
			case 3:
				pref = "low"
			}
			b.WriteString(fmt.Sprintf("    %-40s  %-8s  %s\n",
				rt.Prefix,
				formatDuration(rt.Lifetime),
				pref,
			))
		}
	}

	return b.String()
}

// --- Helper functions (unchanged) ---

type multicastGroupEntry struct {
	Group   string
	Members int
}

// aggregateMulticastGroups collects all multicast groups across peers,
// counts unique members, and returns them sorted by member count descending.
func aggregateMulticastGroups(stats []PeerSummary) []multicastGroupEntry {
	counts := make(map[string]int)
	for _, peer := range stats {
		for _, group := range peer.Groups {
			counts[group]++
		}
	}
	if len(counts) == 0 {
		return nil
	}

	entries := make([]multicastGroupEntry, 0, len(counts))
	for group, members := range counts {
		entries = append(entries, multicastGroupEntry{Group: group, Members: members})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Members != entries[j].Members {
			return entries[i].Members > entries[j].Members
		}
		return entries[i].Group < entries[j].Group
	})
	return entries
}

// multicastLabel returns a human-readable label for well-known multicast groups.
func multicastLabel(group string) string {
	if label, ok := knownMulticastGroups[group]; ok {
		return label
	}
	// Solicited-node multicast: ff02::1:ffXX:XXXX
	if strings.HasPrefix(group, "ff02::1:ff") {
		return "Solicited-Node"
	}
	return ""
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatTimestamp(t time.Time) string {
	return t.Format("15:04:05")
}

func formatDuration(d time.Duration) string {
	if d >= time.Hour {
		hours := d / time.Hour
		mins := (d % time.Hour) / time.Minute
		if mins > 0 {
			return fmt.Sprintf("%dh%dm", hours, mins)
		}
		return fmt.Sprintf("%dh", hours)
	}
	if d >= time.Minute {
		mins := d / time.Minute
		secs := (d % time.Minute) / time.Second
		if secs > 0 {
			return fmt.Sprintf("%dm%ds", mins, secs)
		}
		return fmt.Sprintf("%dm", mins)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}
