package config

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Config 存储整个应用的配置信息
type Config struct {
	DNS       DNSConfig       `json:"dns"`
	BlockList BlockListConfig `json:"block_list"`
	API       APIConfig       `json:"api"`
	Upstream  UpstreamConfig  `json:"upstream"`
	Auth      AuthConfig      `json:"auth"`
}

// DNSConfig DNS服务配置
type DNSConfig struct {
	Port           int      `json:"port"`
	CertFile       string   `json:"cert_file"`
	KeyFile        string   `json:"key_file"`
	AllowedIPs     []string `json:"allowed_ips"`     // 允许访问DNS服务的IP地址列表
	AllowedDomains []string `json:"allowed_domains"` // 允许的域名列表（SNI验证），为空则不限制
	CacheSize      int      `json:"cache_size"`      // DNS缓存大小
	CacheTTL       int      `json:"cache_ttl"`       // DNS缓存TTL(秒)
}

// BlockListConfig 广告域名屏蔽配置
type BlockListConfig struct {
	URLs           []string `json:"urls"`            // 广告域名列表URL
	Whitelist      []string `json:"whitelist"`       // 白名单域名
	UpdateInterval int      `json:"update_interval"` // 更新间隔(小时)
}

// APIConfig API服务配置
type APIConfig struct {
	Port      int    `json:"port"`
	Host      string `json:"host"`
	JWTSecret string `json:"jwt_secret"` // JWT密钥
}

// AuthConfig 认证配置
type AuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UpstreamConfig 上游DNS服务器配置
type UpstreamConfig struct {
	Servers []string `json:"servers"` // 上游DNS服务器列表
	Timeout int      `json:"timeout"` // 超时时间(秒)
	Retries int      `json:"retries"` // 重试次数
}

// SafeConfig 用于API返回的安全配置（隐藏敏感信息）
type SafeConfig struct {
	DNS       SafeDNSConfig   `json:"dns"`
	BlockList BlockListConfig `json:"block_list"`
	API       SafeAPIConfig   `json:"api"`
	Upstream  UpstreamConfig  `json:"upstream"`
	Auth      SafeAuthConfig  `json:"auth"`
}

// SafeDNSConfig 安全的DNS配置
type SafeDNSConfig struct {
	Port           int      `json:"port"`
	CertFile       string   `json:"cert_file"`
	KeyFile        string   `json:"key_file"`
	AllowedIPs     []string `json:"allowed_ips"`
	AllowedDomains []string `json:"allowed_domains"`
	CacheSize      int      `json:"cache_size"`
	CacheTTL       int      `json:"cache_ttl"`
}

// SafeAPIConfig 安全的API配置
type SafeAPIConfig struct {
	Port      int    `json:"port"`
	Host      string `json:"host"`
	JWTSecret string `json:"jwt_secret"`
}

// SafeAuthConfig 安全的认证配置（隐藏用户名和密码）
type SafeAuthConfig struct {
	Enabled bool `json:"enabled"` // 仅显示是否启用了认证
}

// DNSConfigResponse 用于API返回的DNS配置（包含DNS和Upstream信息）
type DNSConfigResponse struct {
	Port           int            `json:"port"`
	CertFile       string         `json:"cert_file"`
	KeyFile        string         `json:"key_file"`
	AllowedIPs     []string       `json:"allowed_ips"`
	AllowedDomains []string       `json:"allowed_domains"`
	CacheSize      int            `json:"cache_size"`
	CacheTTL       int            `json:"cache_ttl"`
	Upstream       UpstreamConfig `json:"upstream"`
}

// BlockListConfigResponse 用于API返回的BlockList配置
type BlockListConfigResponse struct {
	URLs           []string `json:"urls"`
	Whitelist      []string `json:"whitelist"`
	UpdateInterval int      `json:"update_interval"`
}

var (
	cfg  *Config
	db   *sql.DB
	once sync.Once
	mu   sync.RWMutex
)

// hashPassword 使用bcrypt加密密码
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// needsPasswordMigration 检查密码是否需要从明文迁移到bcrypt哈希
func needsPasswordMigration(password string) bool {
	// bcrypt哈希格式: $2a$10$..., $2b$10$..., 等
	// 长度为60个字符，以$2开头
	if len(password) == 60 && strings.HasPrefix(password, "$2") {
		return false // 已经是bcrypt哈希
	}
	return true // 需要迁移
}

// initDatabase 初始化数据库表结构
func initDatabase(database *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS config_dns (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		port INTEGER NOT NULL,
		cert_file TEXT NOT NULL,
		key_file TEXT NOT NULL,
		cache_size INTEGER NOT NULL,
		cache_ttl INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS config_blocklist (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		update_interval INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS config_api (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		port INTEGER NOT NULL,
		host TEXT NOT NULL,
		jwt_secret TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS config_auth (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		username TEXT NOT NULL,
		password TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS config_upstream (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		timeout INTEGER NOT NULL,
		retries INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS upstream_servers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		server TEXT NOT NULL,
		sort_order INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS blocklist_urls (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		url TEXT NOT NULL,
		sort_order INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS blocklist_whitelist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		sort_order INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS allowed_ips (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		sort_order INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS allowed_domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		sort_order INTEGER NOT NULL
	);
	`

	_, err := database.Exec(schema)
	return err
}

// LoadConfig 从SQLite数据库加载配置
func LoadConfig(dbPath string) (*Config, error) {
	var err error

	once.Do(func() {
		cfg = &Config{}
		db, err = sql.Open("sqlite", dbPath)
		if err != nil {
			return
		}

		// 设置连接池参数
		db.SetMaxOpenConns(1) // SQLite 只支持单个写连接
		db.SetMaxIdleConns(1)

		// 初始化数据库表
		if err = initDatabase(db); err != nil {
			return
		}

		// 检查数据库是否为空，如果是则插入默认配置
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM config_dns").Scan(&count)
		if err != nil {
			return
		}

		if count == 0 {
			// 插入默认配置
			defaultConfig := getDefaultConfig()
			err = saveConfigToDB(defaultConfig)
			if err != nil {
				return
			}
		}
	})

	if err != nil {
		return nil, err
	}

	// 从数据库加载配置
	return loadConfigFromDB()
}

// getDefaultConfig 返回默认配置
func getDefaultConfig() *Config {
	return &Config{
		DNS: DNSConfig{
			Port:           853,
			CertFile:       "./certs/cert.pem",
			KeyFile:        "./certs/key.pem",
			AllowedIPs:     []string{"0.0.0.0/0"},
			AllowedDomains: []string{}, // 空表示不限制域名
			CacheSize:      1000,
			CacheTTL:       3600,
		},
		BlockList: BlockListConfig{
			URLs:           []string{"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
			Whitelist:      []string{},
			UpdateInterval: 24,
		},
		API: APIConfig{
			Port:      18080,
			Host:      "0.0.0.0",
			JWTSecret: "default-jwt-secret-please-change",
		},
		Auth: AuthConfig{
			Username: "admin",
			Password: "admin",
		},
		Upstream: UpstreamConfig{
			Servers: []string{"dns.alidns.com"},
			Timeout: 5,
			Retries: 3,
		},
	}
}

// loadConfigFromDB 从数据库加载配置
func loadConfigFromDB() (*Config, error) {
	mu.RLock()
	defer mu.RUnlock()

	config := &Config{}

	// 加载DNS配置
	err := db.QueryRow(`
		SELECT port, cert_file, key_file, cache_size, cache_ttl 
		FROM config_dns WHERE id = 1
	`).Scan(
		&config.DNS.Port,
		&config.DNS.CertFile,
		&config.DNS.KeyFile,
		&config.DNS.CacheSize,
		&config.DNS.CacheTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("加载DNS配置失败: %w", err)
	}

	// 加载允许的IP列表
	rows, err := db.Query("SELECT ip FROM allowed_ips ORDER BY sort_order")
	if err != nil {
		return nil, fmt.Errorf("加载允许的IP列表失败: %w", err)
	}
	defer rows.Close()

	config.DNS.AllowedIPs = []string{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		config.DNS.AllowedIPs = append(config.DNS.AllowedIPs, ip)
	}

	// 加载允许的域名列表
	rows, err = db.Query("SELECT domain FROM allowed_domains ORDER BY sort_order")
	if err != nil {
		return nil, fmt.Errorf("加载允许的域名列表失败: %w", err)
	}
	defer rows.Close()

	config.DNS.AllowedDomains = []string{}
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		config.DNS.AllowedDomains = append(config.DNS.AllowedDomains, domain)
	}

	// 加载BlockList配置
	err = db.QueryRow(`
		SELECT update_interval 
		FROM config_blocklist WHERE id = 1
	`).Scan(&config.BlockList.UpdateInterval)
	if err != nil {
		return nil, fmt.Errorf("加载BlockList配置失败: %w", err)
	}

	// 加载黑名单URLs
	rows, err = db.Query("SELECT url FROM blocklist_urls ORDER BY sort_order")
	if err != nil {
		return nil, fmt.Errorf("加载黑名单URLs失败: %w", err)
	}
	defer rows.Close()

	config.BlockList.URLs = []string{}
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			return nil, err
		}
		config.BlockList.URLs = append(config.BlockList.URLs, url)
	}

	// 加载白名单
	rows, err = db.Query("SELECT domain FROM blocklist_whitelist ORDER BY sort_order")
	if err != nil {
		return nil, fmt.Errorf("加载白名单失败: %w", err)
	}
	defer rows.Close()

	config.BlockList.Whitelist = []string{}
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		config.BlockList.Whitelist = append(config.BlockList.Whitelist, domain)
	}

	// 加载API配置
	err = db.QueryRow(`
		SELECT port, host, jwt_secret 
		FROM config_api WHERE id = 1
	`).Scan(
		&config.API.Port,
		&config.API.Host,
		&config.API.JWTSecret,
	)
	if err != nil {
		return nil, fmt.Errorf("加载API配置失败: %w", err)
	}

	// 加载认证配置
	err = db.QueryRow(`
		SELECT username, password 
		FROM config_auth WHERE id = 1
	`).Scan(
		&config.Auth.Username,
		&config.Auth.Password,
	)
	if err != nil {
		return nil, fmt.Errorf("加载认证配置失败: %w", err)
	}

	// 检查并迁移明文密码为bcrypt哈希
	if needsPasswordMigration(config.Auth.Password) {
		hashedPassword, err := hashPassword(config.Auth.Password)
		if err != nil {
			return nil, fmt.Errorf("迁移密码失败: %w", err)
		}

		// 更新数据库中的密码
		_, err = db.Exec(`
			UPDATE config_auth SET password = ? WHERE id = 1
		`, hashedPassword)
		if err != nil {
			return nil, fmt.Errorf("保存加密密码失败: %w", err)
		}

		config.Auth.Password = hashedPassword
	}

	// 加载上游配置
	err = db.QueryRow(`
		SELECT timeout, retries 
		FROM config_upstream WHERE id = 1
	`).Scan(
		&config.Upstream.Timeout,
		&config.Upstream.Retries,
	)
	if err != nil {
		return nil, fmt.Errorf("加载上游配置失败: %w", err)
	}

	// 加载上游服务器列表
	rows, err = db.Query("SELECT server FROM upstream_servers ORDER BY sort_order")
	if err != nil {
		return nil, fmt.Errorf("加载上游服务器列表失败: %w", err)
	}
	defer rows.Close()

	config.Upstream.Servers = []string{}
	for rows.Next() {
		var server string
		if err := rows.Scan(&server); err != nil {
			return nil, err
		}
		config.Upstream.Servers = append(config.Upstream.Servers, server)
	}

	cfg = config
	return config, nil
}

// saveConfigToDB 保存配置到数据库
func saveConfigToDB(config *Config) error {
	mu.Lock()
	defer mu.Unlock()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer tx.Rollback()

	// 保存DNS配置
	_, err = tx.Exec(`
		INSERT OR REPLACE INTO config_dns (id, port, cert_file, key_file, cache_size, cache_ttl)
		VALUES (1, ?, ?, ?, ?, ?)
	`, config.DNS.Port, config.DNS.CertFile, config.DNS.KeyFile, config.DNS.CacheSize, config.DNS.CacheTTL)
	if err != nil {
		return fmt.Errorf("保存DNS配置失败: %w", err)
	}

	// 保存允许的IP列表
	_, err = tx.Exec("DELETE FROM allowed_ips")
	if err != nil {
		return fmt.Errorf("清空允许的IP列表失败: %w", err)
	}
	for i, ip := range config.DNS.AllowedIPs {
		_, err = tx.Exec("INSERT INTO allowed_ips (ip, sort_order) VALUES (?, ?)", ip, i)
		if err != nil {
			return fmt.Errorf("保存允许的IP失败: %w", err)
		}
	}

	// 保存允许的域名列表
	_, err = tx.Exec("DELETE FROM allowed_domains")
	if err != nil {
		return fmt.Errorf("清空允许的域名列表失败: %w", err)
	}
	for i, domain := range config.DNS.AllowedDomains {
		_, err = tx.Exec("INSERT INTO allowed_domains (domain, sort_order) VALUES (?, ?)", domain, i)
		if err != nil {
			return fmt.Errorf("保存允许的域名失败: %w", err)
		}
	}

	// 保存BlockList配置
	_, err = tx.Exec(`
		INSERT OR REPLACE INTO config_blocklist (id, update_interval)
		VALUES (1, ?)
	`, config.BlockList.UpdateInterval)
	if err != nil {
		return fmt.Errorf("保存BlockList配置失败: %w", err)
	}

	// 保存黑名单URLs
	_, err = tx.Exec("DELETE FROM blocklist_urls")
	if err != nil {
		return fmt.Errorf("清空黑名单URLs失败: %w", err)
	}
	for i, url := range config.BlockList.URLs {
		_, err = tx.Exec("INSERT INTO blocklist_urls (url, sort_order) VALUES (?, ?)", url, i)
		if err != nil {
			return fmt.Errorf("保存黑名单URL失败: %w", err)
		}
	}

	// 保存白名单
	_, err = tx.Exec("DELETE FROM blocklist_whitelist")
	if err != nil {
		return fmt.Errorf("清空白名单失败: %w", err)
	}
	for i, domain := range config.BlockList.Whitelist {
		_, err = tx.Exec("INSERT INTO blocklist_whitelist (domain, sort_order) VALUES (?, ?)", domain, i)
		if err != nil {
			return fmt.Errorf("保存白名单域名失败: %w", err)
		}
	}

	// 保存API配置
	_, err = tx.Exec(`
		INSERT OR REPLACE INTO config_api (id, port, host, jwt_secret)
		VALUES (1, ?, ?, ?)
	`, config.API.Port, config.API.Host, config.API.JWTSecret)
	if err != nil {
		return fmt.Errorf("保存API配置失败: %w", err)
	}

	// 保存认证配置
	_, err = tx.Exec(`
		INSERT OR REPLACE INTO config_auth (id, username, password)
		VALUES (1, ?, ?)
	`, config.Auth.Username, config.Auth.Password)
	if err != nil {
		return fmt.Errorf("保存认证配置失败: %w", err)
	}

	// 保存上游配置
	_, err = tx.Exec(`
		INSERT OR REPLACE INTO config_upstream (id, timeout, retries)
		VALUES (1, ?, ?)
	`, config.Upstream.Timeout, config.Upstream.Retries)
	if err != nil {
		return fmt.Errorf("保存上游配置失败: %w", err)
	}

	// 保存上游服务器列表
	_, err = tx.Exec("DELETE FROM upstream_servers")
	if err != nil {
		return fmt.Errorf("清空上游服务器列表失败: %w", err)
	}
	for i, server := range config.Upstream.Servers {
		_, err = tx.Exec("INSERT INTO upstream_servers (server, sort_order) VALUES (?, ?)", server, i)
		if err != nil {
			return fmt.Errorf("保存上游服务器失败: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	cfg = config
	return nil
}

// SaveConfig 保存配置到数据库
func SaveConfig(dbPath string, config *Config) error {
	return saveConfigToDB(config)
}

// GetConfig 获取当前配置
func GetConfig() *Config {
	mu.RLock()
	defer mu.RUnlock()
	return cfg
}

// UpdateConfig 更新配置并保存到数据库
func UpdateConfig(dbPath string, newConfig *Config) error {
	return saveConfigToDB(newConfig)
}

// ToSafeConfig 将配置转换为安全配置（仅隐藏用户名和密码）
func (c *Config) ToSafeConfig() *SafeConfig {
	return &SafeConfig{
		DNS: SafeDNSConfig{
			Port:           c.DNS.Port,
			CertFile:       c.DNS.CertFile,
			KeyFile:        c.DNS.KeyFile,
			AllowedIPs:     c.DNS.AllowedIPs,
			AllowedDomains: c.DNS.AllowedDomains,
			CacheSize:      c.DNS.CacheSize,
			CacheTTL:       c.DNS.CacheTTL,
		},
		BlockList: c.BlockList,
		API: SafeAPIConfig{
			Port:      c.API.Port,
			Host:      c.API.Host,
			JWTSecret: c.API.JWTSecret,
		},
		Upstream: c.Upstream,
		Auth: SafeAuthConfig{
			Enabled: c.Auth.Username != "" && c.Auth.Password != "",
		},
	}
}

// Close 关闭数据库连接
func Close() error {
	if db != nil {
		return db.Close()
	}
	return nil
}

// ExportToJSON 导出配置为JSON（用于备份）
func ExportToJSON() (string, error) {
	mu.RLock()
	defer mu.RUnlock()

	if cfg == nil {
		return "", fmt.Errorf("配置未加载")
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化配置失败: %w", err)
	}

	return string(data), nil
}

// ImportFromJSON 从JSON导入配置（用于恢复）
func ImportFromJSON(jsonStr string) error {
	var newConfig Config
	if err := json.Unmarshal([]byte(jsonStr), &newConfig); err != nil {
		return fmt.Errorf("解析JSON失败: %w", err)
	}

	return saveConfigToDB(&newConfig)
}
