package blocker

import (
	"bufio"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yuxy/gin_dns/config"
)

// BlockList 管理广告域名黑名单
type BlockList struct {
	blockedDomains map[string]bool
	whitelist      map[string]bool
	mutex          sync.RWMutex
	log            *logrus.Logger
	lastUpdate     time.Time
	cfg            *config.BlockListConfig
	stats          *Stats
}

// Stats 记录拦截统计信息
type Stats struct {
	BlockedRequests  int64
	PassedRequests   int64
	WhitelistedCount int64
	mutex            sync.Mutex
}

// NewBlockList 创建一个新的广告域名列表管理器
// autoLoad: 是否在初始化时自动加载黑名单（true=立即加载，false=延迟加载）
func NewBlockList(cfg *config.BlockListConfig, logger *logrus.Logger, autoLoad bool) *BlockList {
	bl := &BlockList{
		blockedDomains: make(map[string]bool),
		whitelist:      make(map[string]bool),
		log:            logger,
		cfg:            cfg,
		stats: &Stats{
			BlockedRequests:  0,
			PassedRequests:   0,
			WhitelistedCount: 0,
		},
	}

	// 初始化白名单
	for _, domain := range cfg.Whitelist {
		bl.whitelist[domain] = true
	}

	// 根据参数决定是否立即加载广告域名列表
	if autoLoad {
		bl.Update()
	} else {
		logger.Info("黑名单将延迟加载，等待服务启动完成")
	}

	// 启动定时更新
	go bl.scheduleUpdates(cfg.UpdateInterval)

	return bl
}

// Update 从配置的URL更新广告域名列表
func (bl *BlockList) Update() error {
	newBlockedDomains := make(map[string]bool)

	for _, url := range bl.cfg.URLs {
		bl.log.Infof("从 %s 更新广告域名列表", url)

		resp, err := http.Get(url)
		if err != nil {
			bl.log.Errorf("获取广告列表失败: %v", err)
			continue
		}
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			// 跳过注释和空行
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// 解析hosts文件格式 (0.0.0.0 example.com)
			parts := strings.Fields(line)
			if len(parts) >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
				domain := strings.ToLower(parts[1])
				newBlockedDomains[domain] = true
			} else if !strings.Contains(line, " ") {
				// 假设这是一个域名列表格式
				domain := strings.ToLower(line)
				newBlockedDomains[domain] = true
			}
		}

		if err := scanner.Err(); err != nil {
			bl.log.Errorf("读取广告列表失败: %v", err)
		}
	}

	bl.mutex.Lock()
	bl.blockedDomains = newBlockedDomains
	bl.lastUpdate = time.Now()
	bl.mutex.Unlock()

	bl.log.Infof("广告域名列表已更新，共 %d 条记录", len(newBlockedDomains))
	return nil
}

// scheduleUpdates 定时更新广告域名列表
func (bl *BlockList) scheduleUpdates(intervalHours int) {
	ticker := time.NewTicker(time.Duration(intervalHours) * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		if err := bl.Update(); err != nil {
			bl.log.Errorf("更新广告域名列表失败: %v", err)
		}
	}
}

// IsBlocked 检查域名是否在广告黑名单中
func (bl *BlockList) IsBlocked(domain string) bool {
	domain = strings.ToLower(domain)

	// 检查白名单
	bl.mutex.RLock()
	if _, ok := bl.whitelist[domain]; ok {
		bl.mutex.RUnlock()

		bl.stats.mutex.Lock()
		bl.stats.WhitelistedCount++
		bl.stats.PassedRequests++
		bl.stats.mutex.Unlock()

		return false
	}

	// 检查广告域名列表
	blocked := false
	domainParts := strings.Split(domain, ".")
	for i := 0; i < len(domainParts); i++ {
		subDomain := strings.Join(domainParts[i:], ".")
		if _, ok := bl.blockedDomains[subDomain]; ok {
			blocked = true
			break
		}
	}
	bl.mutex.RUnlock()

	bl.stats.mutex.Lock()
	if blocked {
		bl.stats.BlockedRequests++
	} else {
		bl.stats.PassedRequests++
	}
	bl.stats.mutex.Unlock()

	return blocked
}

// UpdateWhitelist 更新白名单
func (bl *BlockList) UpdateWhitelist(whitelist []string) {
	newWhitelist := make(map[string]bool)
	for _, domain := range whitelist {
		newWhitelist[strings.ToLower(domain)] = true
	}

	bl.mutex.Lock()
	bl.whitelist = newWhitelist
	bl.mutex.Unlock()

	bl.log.Infof("白名单已更新，共 %d 条记录", len(whitelist))
}

// UpdateConfig 更新配置并重新加载黑名单
func (bl *BlockList) UpdateConfig(cfg *config.BlockListConfig) error {
	bl.cfg = cfg
	bl.log.Info("BlockList配置已更新，正在重新加载黑名单...")
	return bl.Update()
}

// GetStats 获取拦截统计信息
func (bl *BlockList) GetStats() Stats {
	bl.stats.mutex.Lock()
	defer bl.stats.mutex.Unlock()

	return Stats{
		BlockedRequests:  bl.stats.BlockedRequests,
		PassedRequests:   bl.stats.PassedRequests,
		WhitelistedCount: bl.stats.WhitelistedCount,
	}
}

// GetLastUpdateTime 获取最近更新时间
func (bl *BlockList) GetLastUpdateTime() time.Time {
	bl.mutex.RLock()
	defer bl.mutex.RUnlock()
	return bl.lastUpdate
}

// GetDomainsCount 获取黑名单域名数量
func (bl *BlockList) GetDomainsCount() int {
	bl.mutex.RLock()
	defer bl.mutex.RUnlock()
	return len(bl.blockedDomains)
}
