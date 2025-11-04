package dns

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/yuxy/gin_dns/blocker"
	"github.com/yuxy/gin_dns/config"
)

// DNSServer 是DoT DNS服务器的实现
type DNSServer struct {
	server           *dns.Server
	blocker          *blocker.BlockList
	log              *logrus.Logger
	cfg              *config.Config
	cache            *DNSCache
	stats            *DNSStats
	running          bool
	mutex            sync.Mutex
	upstreamPriority []string     // 动态调整的上游服务器优先级列表
	priorityMutex    sync.RWMutex // 保护优先级列表的互斥锁
}

// DNSStats 包含DNS服务的统计信息
type DNSStats struct {
	Queries        int64
	CacheHits      int64
	CacheMisses    int64
	BlockedQueries int64
	UpstreamErrors int64
	mutex          sync.Mutex
}

// CacheEntry 表示DNS缓存中的一条记录
type CacheEntry struct {
	Msg      *dns.Msg
	ExpireAt time.Time
}

// DNSCache 实现DNS响应缓存
type DNSCache struct {
	entries map[string]CacheEntry
	mutex   sync.RWMutex
	maxSize int
}

// NewDNSServer 创建一个新的DNS服务器实例
func NewDNSServer(cfg *config.Config, blocker *blocker.BlockList, logger *logrus.Logger) (*DNSServer, error) {
	server := &DNSServer{
		blocker: blocker,
		log:     logger,
		cfg:     cfg,
		running: false,
		stats: &DNSStats{
			Queries:        0,
			CacheHits:      0,
			CacheMisses:    0,
			BlockedQueries: 0,
			UpstreamErrors: 0,
		},
		cache: &DNSCache{
			entries: make(map[string]CacheEntry),
			maxSize: cfg.DNS.CacheSize,
		},
		upstreamPriority: make([]string, len(cfg.Upstream.Servers)),
	}

	// 初始化上游服务器优先级列表（复制配置中的顺序）
	copy(server.upstreamPriority, cfg.Upstream.Servers)

	return server, nil
}

// Start 启动DNS服务器
func (s *DNSServer) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.running {
		return fmt.Errorf("DNS服务器已经在运行")
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSRequest)

	cert, err := tls.LoadX509KeyPair(s.cfg.DNS.CertFile, s.cfg.DNS.KeyFile)
	if err != nil {
		return fmt.Errorf("加载TLS证书失败: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// 如果配置了允许的域名列表，启用SNI验证
	if len(s.cfg.DNS.AllowedDomains) > 0 {
		tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// 检查客户端提供的 SNI
			serverName := hello.ServerName

			// 如果客户端没有提供 SNI，拒绝连接
			if serverName == "" {
				s.log.Warnf("拒绝连接：客户端未提供 SNI (来自 %s)", hello.Conn.RemoteAddr())
				return nil, fmt.Errorf("需要提供服务器名称（SNI）")
			}

			// 检查 SNI 是否在允许的域名列表中
			allowed := false
			for _, domain := range s.cfg.DNS.AllowedDomains {
				if serverName == domain {
					allowed = true
					break
				}
			}

			if !allowed {
				s.log.Warnf("拒绝连接：SNI '%s' 不在允许的域名列表中 (来自 %s)", serverName, hello.Conn.RemoteAddr())
				return nil, fmt.Errorf("不允许的服务器名称")
			}

			s.log.Debugf("接受连接：SNI '%s' 验证通过 (来自 %s)", serverName, hello.Conn.RemoteAddr())

			// 返回相同的配置
			return tlsConfig, nil
		}
	}

	s.server = &dns.Server{
		Addr:      fmt.Sprintf(":%d", s.cfg.DNS.Port),
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	go func() {
		if len(s.cfg.DNS.AllowedDomains) > 0 {
			s.log.Infof("启动DNS服务器（DoT/TLS模式）在端口 %d，仅允许域名: %v", s.cfg.DNS.Port, s.cfg.DNS.AllowedDomains)
		} else {
			s.log.Infof("启动DNS服务器（DoT/TLS模式）在端口 %d (不限制域名)", s.cfg.DNS.Port)
		}
		if err := s.server.ListenAndServe(); err != nil {
			s.log.Errorf("DNS服务器出错: %v", err)
		}
	}()

	s.running = true
	return nil
}

// Stop 停止DNS服务器
func (s *DNSServer) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.running {
		return fmt.Errorf("DNS服务器未运行")
	}

	s.log.Info("正在停止DNS服务器")
	err := s.server.Shutdown()
	s.running = false
	return err
}

// handleDNSRequest 处理DNS请求
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	// 记录收到的请求
	if len(r.Question) > 0 {
		s.log.Infof("收到DNS查询: %s (类型: %s)", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype])
	}

	// 更新统计信息
	s.stats.mutex.Lock()
	s.stats.Queries++
	s.stats.mutex.Unlock()

	// 仅处理标准查询
	if r.Opcode != dns.OpcodeQuery {
		dns.HandleFailed(w, r)
		return
	}

	// 创建回复
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true

	// 处理查询
	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			s.handleAddressQuery(r, q, m)
		default:
			// 对于其他类型的查询，直接转发到上游DNS
			s.forwardToUpstream(r, m)
		}
	}

	// 发送回复
	w.WriteMsg(m)
}

// handleAddressQuery 处理A/AAAA记录查询
func (s *DNSServer) handleAddressQuery(r *dns.Msg, q dns.Question, m *dns.Msg) {
	domain := strings.TrimSuffix(q.Name, ".")

	// 检查缓存
	if cachedMsg := s.cache.checkCache(q.Name, q.Qtype); cachedMsg != nil {
		s.stats.mutex.Lock()
		s.stats.CacheHits++
		s.stats.mutex.Unlock()

		m.Answer = append(m.Answer, cachedMsg.Answer...)
		return
	}

	s.stats.mutex.Lock()
	s.stats.CacheMisses++
	s.stats.mutex.Unlock()

	// 检查域名是否在广告黑名单中
	if s.blocker.IsBlocked(domain) {
		s.log.Debugf("已拦截广告域名: %s", domain)

		s.stats.mutex.Lock()
		s.stats.BlockedQueries++
		s.stats.mutex.Unlock()

		// 对于广告域名，返回0.0.0.0或::
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(fmt.Sprintf("%s A 0.0.0.0", q.Name))
			m.Answer = append(m.Answer, rr)
		} else if q.Qtype == dns.TypeAAAA {
			rr, _ := dns.NewRR(fmt.Sprintf("%s AAAA ::", q.Name))
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	// 转发到上游DNS
	s.forwardToUpstream(r, m)
}

// forwardToUpstream 将查询转发到上游DNS服务器
func (s *DNSServer) forwardToUpstream(r *dns.Msg, m *dns.Msg) {
	if len(r.Question) > 0 {
		s.log.Infof("转发查询到上游: %s", r.Question[0].Name)
	}

	var resp *dns.Msg
	var err error
	var lastErr error

	// 获取当前优先级列表的副本
	s.priorityMutex.RLock()
	upstreamList := make([]string, len(s.upstreamPriority))
	copy(upstreamList, s.upstreamPriority)
	s.priorityMutex.RUnlock()

	// 如果优先级列表为空或配置已更新，重新同步
	if len(upstreamList) == 0 || len(upstreamList) != len(s.cfg.Upstream.Servers) {
		s.priorityMutex.Lock()
		s.upstreamPriority = make([]string, len(s.cfg.Upstream.Servers))
		copy(s.upstreamPriority, s.cfg.Upstream.Servers)
		upstreamList = make([]string, len(s.upstreamPriority))
		copy(upstreamList, s.upstreamPriority)
		s.priorityMutex.Unlock()
		s.log.Info("上游服务器列表已更新，重新初始化优先级")
	}

	// 尝试所有上游DNS服务器
	for idx, server := range upstreamList {
		// 确保有端口号
		serverAddr := server
		if !strings.Contains(serverAddr, ":") {
			serverAddr = serverAddr + ":853" // DoT默认端口
		}

		// 提取服务器主机名（用于SNI）
		serverName := server
		if strings.Contains(server, ":") {
			// 如果包含端口，去掉端口部分
			serverName = strings.Split(server, ":")[0]
		}

		s.log.Infof("尝试连接上游服务器: %s (SNI: %s, 优先级: %d/%d)", serverAddr, serverName, idx+1, len(upstreamList))

		// 为每个服务器创建独立的客户端配置
		c := &dns.Client{
			Net:     "tcp-tls", // 使用DNS over TLS
			Timeout: time.Duration(s.cfg.Upstream.Timeout) * time.Second,
			TLSConfig: &tls.Config{
				ServerName:         serverName, // 使用实际的服务器名称
				InsecureSkipVerify: false,
			},
		}

		allRetriesFailed := true
		for i := 0; i < s.cfg.Upstream.Retries; i++ {
			resp, _, err = c.Exchange(r, serverAddr)
			if err != nil {
				lastErr = err
				s.log.Infof("第%d次尝试失败 (%s): %v", i+1, serverAddr, err)
				continue
			}

			if resp.Rcode == dns.RcodeServerFailure {
				s.log.Infof("服务器返回失败响应: %s", serverAddr)
				continue
			}

			// 成功获取响应
			s.log.Debugf("成功从 %s 获取响应", serverAddr)
			allRetriesFailed = false

			// 保存到缓存
			if len(resp.Answer) > 0 {
				s.updateCache(r.Question[0].Name, r.Question[0].Qtype, resp)
			}

			m.Answer = append(m.Answer, resp.Answer...)
			m.Ns = append(m.Ns, resp.Ns...)
			m.Extra = append(m.Extra, resp.Extra...)
			return
		}

		// 如果是第一个服务器且所有重试都失败，并且有多个上游服务器，降低其优先级
		if idx == 0 && allRetriesFailed && len(upstreamList) > 1 {
			s.demoteUpstreamPriority(server)
		}
	}

	s.stats.mutex.Lock()
	s.stats.UpstreamErrors++
	s.stats.mutex.Unlock()

	if lastErr != nil {
		s.log.Errorf("所有上游DNS服务器均无响应，最后错误: %v", lastErr)
	} else {
		s.log.Errorf("所有上游DNS服务器均无响应")
	}
	m.Rcode = dns.RcodeServerFailure
}

// demoteUpstreamPriority 降低指定上游服务器的优先级（移到列表末尾）
func (s *DNSServer) demoteUpstreamPriority(server string) {
	s.priorityMutex.Lock()
	defer s.priorityMutex.Unlock()

	// 只有在有多个上游服务器时才调整优先级
	if len(s.upstreamPriority) <= 1 {
		return
	}

	// 查找服务器在列表中的位置
	idx := -1
	for i, srv := range s.upstreamPriority {
		if srv == server {
			idx = i
			break
		}
	}

	// 如果找到且不是最后一个，移到末尾
	if idx >= 0 && idx < len(s.upstreamPriority)-1 {
		// 移除当前位置的服务器
		s.upstreamPriority = append(s.upstreamPriority[:idx], s.upstreamPriority[idx+1:]...)
		// 添加到末尾
		s.upstreamPriority = append(s.upstreamPriority, server)

		s.log.Warnf("上游服务器 %s 连续失败，优先级已降低（移至末尾），当前顺序: %v", server, s.upstreamPriority)
	}
}

// checkCache 检查缓存中是否有对应的记录
func (s *DNSCache) checkCache(name string, qtype uint16) *dns.Msg {
	key := fmt.Sprintf("%s:%d", name, qtype)

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if entry, ok := s.entries[key]; ok {
		// 检查是否过期
		if time.Now().Before(entry.ExpireAt) {
			return entry.Msg
		}
		// 过期了，删除
		delete(s.entries, key)
	}

	return nil
}

// updateCache 更新缓存
func (s *DNSServer) updateCache(name string, qtype uint16, msg *dns.Msg) {
	if len(msg.Answer) == 0 {
		return
	}

	s.cache.mutex.Lock()
	defer s.cache.mutex.Unlock()

	// 如果缓存已满，删除一条记录
	if len(s.cache.entries) >= s.cache.maxSize {
		// 简单策略：随机删除一条
		for k := range s.cache.entries {
			delete(s.cache.entries, k)
			break
		}
	}

	// 找出最小TTL
	minTTL := uint32(s.cfg.DNS.CacheTTL) // 默认缓存时间(秒)
	for _, rr := range msg.Answer {
		if ttl := rr.Header().Ttl; ttl < minTTL {
			minTTL = ttl
		}
	}

	// 添加到缓存
	key := fmt.Sprintf("%s:%d", name, qtype)
	s.cache.entries[key] = CacheEntry{
		Msg:      msg.Copy(),
		ExpireAt: time.Now().Add(time.Duration(minTTL) * time.Second),
	}
}

// GetStats 获取DNS服务统计信息
func (s *DNSServer) GetStats() DNSStats {
	s.stats.mutex.Lock()
	defer s.stats.mutex.Unlock()

	return DNSStats{
		Queries:        s.stats.Queries,
		CacheHits:      s.stats.CacheHits,
		CacheMisses:    s.stats.CacheMisses,
		BlockedQueries: s.stats.BlockedQueries,
		UpstreamErrors: s.stats.UpstreamErrors,
	}
}

// IsRunning 检查DNS服务器是否运行中
func (s *DNSServer) IsRunning() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.running
}

// ClearCache 清除DNS缓存
func (s *DNSServer) ClearCache() {
	s.cache.mutex.Lock()
	defer s.cache.mutex.Unlock()

	s.cache.entries = make(map[string]CacheEntry)
}
