package domain

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Decision is the only set of actions that the enforcement layer may receive.
type Decision string

const (
	DecisionAllow     Decision = "ALLOW"
	DecisionDrop      Decision = "DROP"
	DecisionReject    Decision = "REJECT"
	DecisionRateLimit Decision = "RATE_LIMIT"
	DecisionReset     Decision = "RESET_SESSION"
	DecisionTempBlock Decision = "TEMP_BLOCK"
)

func (d Decision) Valid() bool {
	switch d {
	case DecisionAllow, DecisionDrop, DecisionReject, DecisionRateLimit, DecisionReset, DecisionTempBlock:
		return true
	default:
		return false
	}
}

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

func (s Severity) Weight() int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 10
	case SeverityMedium:
		return 20
	case SeverityHigh:
		return 30
	case SeverityCritical:
		return 40
	default:
		return 0
	}
}

type TLSMode string

const (
	TLSBypass   TLSMode = "BYPASS"
	TLSMetadata TLSMode = "METADATA_ONLY"
	TLSDecrypt  TLSMode = "DECRYPT"
)

func (m TLSMode) Valid() bool {
	return m == TLSBypass || m == TLSMetadata || m == TLSDecrypt
}

type InterfaceMode string

const (
	InterfaceL3         InterfaceMode = "L3"
	InterfaceVLANParent InterfaceMode = "VLAN_PARENT"
	InterfaceVLANSub    InterfaceMode = "VLAN_SUBINTERFACE"
	InterfaceManagement InterfaceMode = "MANAGEMENT"
)

func (m InterfaceMode) Valid() bool {
	switch m {
	case InterfaceL3, InterfaceVLANParent, InterfaceVLANSub, InterfaceManagement:
		return true
	default:
		return false
	}
}

type Interface struct {
	ID                string        `json:"id"`
	Name              string        `json:"name"`
	SystemName        string        `json:"system_name"`
	MACAddress        string        `json:"mac_address"`
	ZoneID            string        `json:"zone_id"`
	Mode              InterfaceMode `json:"mode"`
	ParentInterfaceID string        `json:"parent_interface_id,omitempty"`
	VLANID            int           `json:"vlan_id,omitempty"`
	IPv4Addresses     []string      `json:"ipv4_addresses"`
	IPv6Addresses     []string      `json:"ipv6_addresses"`
	MTU               int           `json:"mtu"`
	AdminState        bool          `json:"admin_state"`
	LinkState         string        `json:"link_state"`
	RxPackets         uint64        `json:"rx_packets"`
	TxPackets         uint64        `json:"tx_packets"`
	RxBytes           uint64        `json:"rx_bytes"`
	TxBytes           uint64        `json:"tx_bytes"`
}

type Zone struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Route struct {
	ID              string `json:"id"`
	DestinationCIDR string `json:"destination_cidr"`
	Gateway         string `json:"gateway"`
	InterfaceID     string `json:"interface_id"`
	Metric          int    `json:"metric"`
	Enabled         bool   `json:"enabled"`
	Description     string `json:"description"`
}

type NATRule struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Type               string `json:"type"`
	SourceZone         string `json:"source_zone"`
	DestinationZone    string `json:"destination_zone"`
	SourceNetwork      string `json:"source_network"`
	DestinationNetwork string `json:"destination_network"`
	Protocol           string `json:"protocol"`
	OriginalPort       int    `json:"original_port"`
	TranslatedAddress  string `json:"translated_address"`
	TranslatedPort     int    `json:"translated_port"`
	Enabled            bool   `json:"enabled"`
	Priority           int    `json:"priority"`
}

type FlowKey struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Protocol  string `json:"protocol"`
	Namespace string `json:"namespace"`
}

func (k FlowKey) Reverse() FlowKey {
	return FlowKey{SrcIP: k.DstIP, DstIP: k.SrcIP, SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol, Namespace: k.Namespace}
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d-%s:%d/%s/%s", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, strings.ToUpper(k.Protocol), k.Namespace)
}

type Session struct {
	ID                    string        `json:"id"`
	ClientIP              string        `json:"client_ip"`
	ClientPort            int           `json:"client_port"`
	ServerIP              string        `json:"server_ip"`
	ServerPort            int           `json:"server_port"`
	Protocol              string        `json:"protocol"`
	SourceZone            string        `json:"source_zone"`
	DestinationZone       string        `json:"destination_zone"`
	StartTime             time.Time     `json:"start_time"`
	LastSeen              time.Time     `json:"last_seen"`
	Timeout               time.Duration `json:"timeout"`
	TCPState              string        `json:"tcp_state"`
	PacketsUp             uint64        `json:"packets_up"`
	PacketsDown           uint64        `json:"packets_down"`
	BytesUp               uint64        `json:"bytes_up"`
	BytesDown             uint64        `json:"bytes_down"`
	Application           string        `json:"application"`
	ApplicationConfidence float64       `json:"application_confidence"`
	SecurityContextID     string        `json:"security_context_id"`
	PolicyID              string        `json:"policy_id"`
	PolicyVersion         uint64        `json:"policy_version"`
	DecisionVersion       uint64        `json:"decision_version"`
	RiskScore             int           `json:"risk_score"`
	Decision              Decision      `json:"decision"`
	FastPathEligible      bool          `json:"fast_path_eligible"`
	FastPathReason        string        `json:"fast_path_reason,omitempty"`
	Invalidated           bool          `json:"invalidated"`
	OriginalTuple         *FlowKey      `json:"original_tuple,omitempty"`
	ReplyTuple            *FlowKey      `json:"reply_tuple,omitempty"`
}

type NetworkContext struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  int    `json:"src_port"`
	DstPort  int    `json:"dst_port"`
	Protocol string `json:"protocol"`
	SrcZone  string `json:"src_zone"`
	DstZone  string `json:"dst_zone"`
}

type ApplicationContext struct {
	Protocol    string  `json:"protocol"`
	Application string  `json:"application"`
	Confidence  float64 `json:"confidence"`
	Hostname    string  `json:"hostname,omitempty"`
	URL         string  `json:"url,omitempty"`
	Method      string  `json:"method,omitempty"`
	ContentType string  `json:"content_type,omitempty"`
}

type TLSContext struct {
	SNI          string `json:"sni,omitempty"`
	TLSVersion   string `json:"tls_version,omitempty"`
	Cipher       string `json:"cipher,omitempty"`
	CertSubject  string `json:"cert_subject,omitempty"`
	CertIssuer   string `json:"cert_issuer,omitempty"`
	CertValidity string `json:"cert_validity,omitempty"`
	ALPN         string `json:"alpn,omitempty"`
	Decrypted    bool   `json:"decrypted"`
	Available    bool   `json:"available"`
}

type DNSContext struct {
	Query        string   `json:"query,omitempty"`
	RecordType   string   `json:"record_type,omitempty"`
	Answers      []string `json:"answers,omitempty"`
	ResponseCode int      `json:"response_code,omitempty"`
	TTL          uint32   `json:"ttl,omitempty"`
}

type ReputationContext struct {
	SrcIPScore   int      `json:"src_ip_score"`
	DstIPScore   int      `json:"dst_ip_score"`
	DomainScore  int      `json:"domain_score"`
	MatchedLists []string `json:"matched_lists,omitempty"`
}

type IPSContext struct {
	Alerts      []SecurityEvent `json:"alerts,omitempty"`
	MaxSeverity Severity        `json:"max_severity,omitempty"`
}

type BehaviorContext struct {
	AnomalyEvents []SecurityEvent `json:"anomaly_events,omitempty"`
}

type MLContext struct {
	PredictedClass string             `json:"predicted_class,omitempty"`
	Confidence     float64            `json:"confidence"`
	Probabilities  map[string]float64 `json:"probabilities,omitempty"`
	ModelVersion   string             `json:"model_version,omitempty"`
	Available      bool               `json:"available"`
}

type RiskContribution struct {
	Source     string  `json:"source"`
	Value      int     `json:"value"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

type RiskContext struct {
	Score         int                `json:"score"`
	Level         string             `json:"level"`
	Reasons       []string           `json:"reasons,omitempty"`
	Contributions []RiskContribution `json:"contributions,omitempty"`
}

type PolicyContext struct {
	MatchedPolicyID string   `json:"matched_policy_id,omitempty"`
	Action          Decision `json:"action"`
	Scope           string   `json:"scope,omitempty"`
	Reason          string   `json:"reason,omitempty"`
}

type SecurityContext struct {
	FlowID     string             `json:"flow_id"`
	SessionID  string             `json:"session_id"`
	Network    NetworkContext     `json:"network"`
	App        ApplicationContext `json:"app"`
	TLS        TLSContext         `json:"tls"`
	DNS        DNSContext         `json:"dns"`
	Reputation ReputationContext  `json:"reputation"`
	IPS        IPSContext         `json:"ips"`
	Behavior   BehaviorContext    `json:"behavior"`
	ML         MLContext          `json:"ml"`
	Risk       RiskContext        `json:"risk"`
	Policy     PolicyContext      `json:"policy"`
	Signals    []SecurityEvent    `json:"signals,omitempty"`
	UpdatedAt  time.Time          `json:"updated_at"`
}

type SecurityEvent struct {
	EventID           string         `json:"event_id"`
	Timestamp         time.Time      `json:"timestamp"`
	FlowID            string         `json:"flow_id,omitempty"`
	SessionID         string         `json:"session_id,omitempty"`
	Detector          string         `json:"detector"`
	Category          string         `json:"category"`
	SignatureID       string         `json:"signature_id,omitempty"`
	Severity          Severity       `json:"severity"`
	Confidence        float64        `json:"confidence"`
	SourceIP          string         `json:"source_ip,omitempty"`
	DestinationIP     string         `json:"destination_ip,omitempty"`
	Application       string         `json:"application,omitempty"`
	Evidence          string         `json:"evidence,omitempty"`
	RecommendedAction string         `json:"recommended_action,omitempty"`
	Metadata          map[string]any `json:"metadata,omitempty"`
}

type SecurityPolicy struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Priority             int      `json:"priority"`
	SourceZones          []string `json:"source_zones,omitempty"`
	DestinationZones     []string `json:"destination_zones,omitempty"`
	SourceAddresses      []string `json:"source_addresses,omitempty"`
	DestinationAddresses []string `json:"destination_addresses,omitempty"`
	Services             []string `json:"services,omitempty"`
	Applications         []string `json:"applications,omitempty"`
	SecurityProfileID    string   `json:"security_profile_id,omitempty"`
	MinimumRisk          *int     `json:"minimum_risk,omitempty"`
	MaximumRisk          *int     `json:"maximum_risk,omitempty"`
	Action               Decision `json:"action"`
	Scope                string   `json:"scope,omitempty"`
	LogStart             bool     `json:"log_start"`
	LogEnd               bool     `json:"log_end"`
	Enabled              bool     `json:"enabled"`
}

type SecurityProfile struct {
	ID                      string   `json:"id"`
	Name                    string   `json:"name"`
	IDSIPSEnabled           bool     `json:"ids_ips_enabled"`
	DPIEnabled              bool     `json:"dpi_enabled"`
	DNSSecurityEnabled      bool     `json:"dns_security_enabled"`
	URLFilteringEnabled     bool     `json:"url_filtering_enabled"`
	ThreatIntelEnabled      bool     `json:"threat_intel_enabled"`
	BehaviorEnabled         bool     `json:"behavior_enabled"`
	MLDetectionEnabled      bool     `json:"ml_detection_enabled"`
	TLSMode                 TLSMode  `json:"tls_mode"`
	MinimumBlockRisk        int      `json:"minimum_block_risk"`
	LoggingLevel            string   `json:"logging_level"`
	InspectionRequired      bool     `json:"inspection_required"`
	InspectionFailureAction Decision `json:"inspection_failure_action"`
}

type TemporaryBlock struct {
	ID          string    `json:"id"`
	Indicator   string    `json:"indicator"`
	Reason      string    `json:"reason"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	SourceEvent string    `json:"source_event,omitempty"`
}

type ReputationEntry struct {
	Indicator       string `json:"indicator"`
	IndicatorType   string `json:"indicator_type"`
	ReputationScore int    `json:"reputation_score"`
	Category        string `json:"category,omitempty"`
	Source          string `json:"source,omitempty"`
	FirstSeen       int64  `json:"first_seen"`
	LastUpdated     int64  `json:"last_updated"`
	ExpiresAt       int64  `json:"expires_at"`
	Enabled         bool   `json:"enabled"`
}

// AuditEntry records a management-plane action. It intentionally contains
// metadata only; credentials, request bodies and packet payloads are excluded.
type AuditEntry struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`
	Role       string    `json:"role,omitempty"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	ResourceID string    `json:"resource_id,omitempty"`
	Result     string    `json:"result"`
	Message    string    `json:"message,omitempty"`
}

type Config struct {
	Interfaces                     []Interface       `json:"interfaces"`
	Zones                          []Zone            `json:"zones"`
	Routes                         []Route           `json:"routes"`
	NATRules                       []NATRule         `json:"nat_rules"`
	Policies                       []SecurityPolicy  `json:"policies"`
	Profiles                       []SecurityProfile `json:"security_profiles"`
	MaxSessions                    int               `json:"max_sessions"`
	MaxEventsQueue                 int               `json:"max_events_queue"`
	MaxHTTPBodyInspection          int               `json:"max_http_body_inspection"`
	MaxHTTPHeaderSize              int               `json:"max_http_header_size"`
	MaxURLLength                   int               `json:"max_url_length"`
	MaxMLInputLength               int               `json:"max_ml_input_length"`
	MLTimeoutMillis                int               `json:"ml_timeout_millis"`
	RequestInspectionTimeoutMillis int               `json:"request_inspection_timeout_millis"`
	DefaultDeny                    bool              `json:"default_deny"`
}

type ConfigVersion struct {
	Version   uint64    `json:"version"`
	Author    string    `json:"author"`
	Timestamp time.Time `json:"timestamp"`
	Comment   string    `json:"comment"`
	Checksum  string    `json:"checksum"`
}

type PolicyDecision struct {
	Action        Decision   `json:"action"`
	Scope         string     `json:"scope"`
	PolicyID      string     `json:"policy_id,omitempty"`
	ConfigVersion uint64     `json:"config_version"`
	Reason        string     `json:"reason"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	RatePerSecond int        `json:"rate_per_second,omitempty"`
	Burst         int        `json:"burst,omitempty"`
}

type ComponentHealth struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

var identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func ValidateIdentifier(name string) error {
	if !identifierPattern.MatchString(name) {
		return fmt.Errorf("invalid identifier %q", name)
	}
	return nil
}

func ValidateCIDR(value string) error {
	if value == "" {
		return errors.New("CIDR is required")
	}
	if _, _, err := net.ParseCIDR(value); err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", value, err)
	}
	return nil
}

func ValidateIP(value string) error {
	if value == "" {
		return errors.New("IP is required")
	}
	if net.ParseIP(value) == nil {
		return fmt.Errorf("invalid IP %q", value)
	}
	return nil
}

func ValidatePort(port int, optional bool) error {
	if optional && port == 0 {
		return nil
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d is outside 1..65535", port)
	}
	return nil
}

func SortPolicies(policies []SecurityPolicy) {
	sort.SliceStable(policies, func(i, j int) bool { return policies[i].Priority < policies[j].Priority })
}
