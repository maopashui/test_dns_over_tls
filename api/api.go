package api

import (
	"embed"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/yuxy/gin_dns/blocker"
	"github.com/yuxy/gin_dns/config"
	"github.com/yuxy/gin_dns/dns"
)

// API 处理HTTP API请求
type API struct {
	router      *gin.Engine
	log         *logrus.Logger
	config      *config.Config
	dbPath      string
	dnsServer   *dns.DNSServer
	blocker     *blocker.BlockList
	staticFiles *embed.FS
}

// NewAPI 创建一个新的API服务实例
func NewAPI(cfg *config.Config, dbPath string, dnsServer *dns.DNSServer, blocker *blocker.BlockList, staticFiles *embed.FS, logger *logrus.Logger) *API {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(corsMiddleware()) // 添加CORS支持

	api := &API{
		router:      router,
		log:         logger,
		config:      cfg,
		dbPath:      dbPath,
		dnsServer:   dnsServer,
		blocker:     blocker,
		staticFiles: staticFiles,
	}

	api.setupRoutes()
	return api
}

// corsMiddleware CORS中间件
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// setupRoutes 设置API路由
func (a *API) setupRoutes() {
	// API版本前缀
	v1 := a.router.Group("/api/v1")

	// 登录接口（无需认证）
	v1.POST("/login", a.login)

	// 需要JWT认证的路由组
	protected := v1.Group("")
	protected.Use(a.JWTAuthMiddleware())
	{
		// 状态和监控
		protected.GET("/status", a.getStatus)

		// 配置管理
		protected.GET("/config", a.getConfig)
		protected.PUT("/config", a.updateConfig)

		// BlockList配置管理
		protected.GET("/config/blocklist", a.getBlockListConfig)
		protected.PUT("/config/blocklist", a.updateBlockListConfig)

		// 认证管理
		protected.POST("/auth/change-password", a.changePassword)

		// DNS服务控制
		protected.POST("/dns/start", a.startDNS)
		protected.POST("/dns/stop", a.stopDNS)
		protected.DELETE("/dns/cache", a.clearDNSCache)
	}

	// 设置静态文件服务
	a.setupStaticFiles()
}

// setupStaticFiles 设置静态文件服务
func (a *API) setupStaticFiles() {
	if a.staticFiles == nil {
		a.log.Warn("静态文件未嵌入，跳过静态文件服务设置")
		return
	}

	// 从 embed.FS 中获取 dist 子目录
	distFS, err := fs.Sub(*a.staticFiles, "dist")
	if err != nil {
		a.log.Errorf("无法获取dist子目录: %v", err)
		return
	}

	// 创建文件服务器
	fileServer := http.FileServer(http.FS(distFS))

	// 添加静态文件路由（作为回退路由）
	a.router.NoRoute(func(c *gin.Context) {
		// 如果是API路径，返回404
		if len(c.Request.URL.Path) >= 4 && c.Request.URL.Path[:4] == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "API路由不存在"})
			return
		}

		// 否则尝试提供静态文件
		fileServer.ServeHTTP(c.Writer, c.Request)
	})

	a.log.Info("静态文件服务已设置（dist目录）")
}

// Start 启动API服务
func (a *API) Start() error {
	addr := a.config.API.Host + ":" + strconv.Itoa(a.config.API.Port)
	a.log.Infof("启动API服务器在 %s", addr)
	return a.router.Run(addr)
}

// 处理程序: 获取系统状态
func (a *API) getStatus(c *gin.Context) {
	dnsStats := a.dnsServer.GetStats()
	blockerStats := a.blocker.GetStats()

	c.JSON(http.StatusOK, gin.H{
		"status": "running",
		"time":   time.Now(),
		"dns": gin.H{
			"running":         a.dnsServer.IsRunning(),
			"queries":         dnsStats.Queries,
			"cache_hits":      dnsStats.CacheHits,
			"cache_misses":    dnsStats.CacheMisses,
			"blocked":         dnsStats.BlockedQueries,
			"upstream_errors": dnsStats.UpstreamErrors,
		},
		"blocker": gin.H{
			"domains_count":    a.blocker.GetDomainsCount(),
			"blocked_requests": blockerStats.BlockedRequests,
			"passed_requests":  blockerStats.PassedRequests,
			"whitelisted":      blockerStats.WhitelistedCount,
			"last_update":      a.blocker.GetLastUpdateTime(),
		},
	})
}

// 处理程序: 获取当前DNS配置（包含DNS和Upstream信息）
func (a *API) getConfig(c *gin.Context) {
	dnsConfig := config.DNSConfigResponse{
		Port:           a.config.DNS.Port,
		CertFile:       a.config.DNS.CertFile,
		KeyFile:        a.config.DNS.KeyFile,
		AllowedIPs:     a.config.DNS.AllowedIPs,
		AllowedDomains: a.config.DNS.AllowedDomains,
		CacheSize:      a.config.DNS.CacheSize,
		CacheTTL:       a.config.DNS.CacheTTL,
		Upstream:       a.config.Upstream,
	}
	c.JSON(http.StatusOK, dnsConfig)
}

// 处理程序: 更新DNS配置（包含DNS和Upstream信息）
func (a *API) updateConfig(c *gin.Context) {
	var dnsConfig config.DNSConfigResponse
	if err := c.ShouldBindJSON(&dnsConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的配置格式: " + err.Error()})
		return
	}

	// 检查配置是否有实质性变化
	configChanged := a.config.DNS.Port != dnsConfig.Port ||
		a.config.DNS.CertFile != dnsConfig.CertFile ||
		a.config.DNS.KeyFile != dnsConfig.KeyFile ||
		!equalStringSlices(a.config.DNS.AllowedIPs, dnsConfig.AllowedIPs) ||
		!equalStringSlices(a.config.DNS.AllowedDomains, dnsConfig.AllowedDomains) ||
		a.config.DNS.CacheSize != dnsConfig.CacheSize ||
		a.config.DNS.CacheTTL != dnsConfig.CacheTTL ||
		!equalStringSlices(a.config.Upstream.Servers, dnsConfig.Upstream.Servers) ||
		a.config.Upstream.Timeout != dnsConfig.Upstream.Timeout ||
		a.config.Upstream.Retries != dnsConfig.Upstream.Retries

	// 更新DNS和Upstream配置
	a.config.DNS.Port = dnsConfig.Port
	a.config.DNS.CertFile = dnsConfig.CertFile
	a.config.DNS.KeyFile = dnsConfig.KeyFile
	a.config.DNS.AllowedIPs = dnsConfig.AllowedIPs
	a.config.DNS.AllowedDomains = dnsConfig.AllowedDomains
	a.config.DNS.CacheSize = dnsConfig.CacheSize
	a.config.DNS.CacheTTL = dnsConfig.CacheTTL
	a.config.Upstream = dnsConfig.Upstream

	// 保存新配置到数据库
	if err := config.UpdateConfig(a.dbPath, a.config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存配置到数据库失败: " + err.Error()})
		return
	}

	// 如果配置有变化且DNS服务正在运行，则热重载
	if configChanged && a.dnsServer.IsRunning() {
		a.log.Info("检测到配置变化，正在热重载DNS服务...")

		// 停止DNS服务
		if err := a.dnsServer.Stop(); err != nil {
			a.log.Errorf("停止DNS服务失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "停止DNS服务失败: " + err.Error()})
			return
		}

		// 使用新配置启动DNS服务
		if err := a.dnsServer.Start(); err != nil {
			a.log.Errorf("启动DNS服务失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "启动DNS服务失败: " + err.Error()})
			return
		}

		a.log.Info("DNS服务热重载完成")
		c.JSON(http.StatusOK, gin.H{"status": "DNS配置已更新并已热重载服务"})
	} else {
		c.JSON(http.StatusOK, gin.H{"status": "DNS配置已更新到数据库"})
	}
}

// 处理程序: 启动DNS服务
func (a *API) startDNS(c *gin.Context) {
	if a.dnsServer.IsRunning() {
		c.JSON(http.StatusOK, gin.H{"status": "DNS服务已经在运行"})
		return
	}

	if err := a.dnsServer.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "启动DNS服务失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "DNS服务已启动"})
}

// 处理程序: 停止DNS服务
func (a *API) stopDNS(c *gin.Context) {
	if !a.dnsServer.IsRunning() {
		c.JSON(http.StatusOK, gin.H{"status": "DNS服务未运行"})
		return
	}

	if err := a.dnsServer.Stop(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "停止DNS服务失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "DNS服务已停止"})
}

// 处理程序: 清除DNS缓存
func (a *API) clearDNSCache(c *gin.Context) {
	a.dnsServer.ClearCache()
	c.JSON(http.StatusOK, gin.H{"status": "DNS缓存已清除"})
}

// 处理程序: 获取BlockList配置
func (a *API) getBlockListConfig(c *gin.Context) {
	blockListConfig := config.BlockListConfigResponse{
		URLs:           a.config.BlockList.URLs,
		Whitelist:      a.config.BlockList.Whitelist,
		UpdateInterval: a.config.BlockList.UpdateInterval,
	}
	c.JSON(http.StatusOK, blockListConfig)
}

// 处理程序: 更新BlockList配置
func (a *API) updateBlockListConfig(c *gin.Context) {
	var blockListConfig config.BlockListConfigResponse
	if err := c.ShouldBindJSON(&blockListConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的配置格式: " + err.Error()})
		return
	}

	// 检查白名单是否有变化
	whitelistChanged := !equalStringSlices(a.config.BlockList.Whitelist, blockListConfig.Whitelist)

	// 检查黑名单URLs是否有变化
	urlsChanged := !equalStringSlices(a.config.BlockList.URLs, blockListConfig.URLs)

	// 更新BlockList配置
	a.config.BlockList.URLs = blockListConfig.URLs
	a.config.BlockList.Whitelist = blockListConfig.Whitelist
	a.config.BlockList.UpdateInterval = blockListConfig.UpdateInterval

	// 如果白名单有变化，立即更新blocker的白名单
	if whitelistChanged {
		a.blocker.UpdateWhitelist(blockListConfig.Whitelist)
		a.log.Info("白名单已热更新")
	}

	// 如果黑名单URLs有变化，需要更新blocker的配置并重新加载
	if urlsChanged {
		if err := a.blocker.UpdateConfig(&a.config.BlockList); err != nil {
			a.log.Errorf("更新黑名单失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新黑名单失败: " + err.Error()})
			return
		}
		a.log.Info("黑名单URLs已更新并重新加载")
	}

	// 保存新配置到数据库
	if err := config.UpdateConfig(a.dbPath, a.config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存配置到数据库失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "BlockList配置已更新并立即生效"})
}

// equalStringSlices 比较两个字符串切片是否相等
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
