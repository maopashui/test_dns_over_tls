package main

import (
	"embed"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/yuxy/gin_dns/api"
	"github.com/yuxy/gin_dns/blocker"
	"github.com/yuxy/gin_dns/config"
	"github.com/yuxy/gin_dns/dns"
)

//go:embed all:dist
var staticFiles embed.FS

var (
	dbPath   = flag.String("db", "./config.db", "配置数据库路径")
	logLevel = flag.String("log-level", "info", "日志级别 (debug, info, warn, error)")
)

func main() {
	flag.Parse()

	// 初始化日志
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// 设置日志级别
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("无效的日志级别: %v", err)
	}
	log.SetLevel(level)

	log.Info("gin_dns服务启动中...")

	// 确保 certs 目录存在
	if err := os.MkdirAll("certs", 0755); err != nil {
		log.Warnf("创建 certs 目录失败: %v", err)
	} else {
		log.Info("certs 目录已准备就绪")
	}

	// 加载配置（从SQLite数据库）
	cfg, err := config.LoadConfig(*dbPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	log.Info("配置已从数据库加载")

	// 创建广告域名拦截器（延迟加载黑名单）
	blockList := blocker.NewBlockList(&cfg.BlockList, log, false)
	log.Info("广告域名拦截器已创建（黑名单延迟加载）")

	// 创建DNS服务器
	dnsServer, err := dns.NewDNSServer(cfg, blockList, log)
	if err != nil {
		log.Fatalf("创建DNS服务器失败: %v", err)
	}

	// 启动DNS服务
	if err := dnsServer.Start(); err != nil {
		log.Warnf("DNS服务器启动失败: %v", err)
		log.Warn("DNS服务未启动，请配置正确的证书后通过API手动启动")
	} else {
		log.Infof("DNS服务已启动在端口 %d", cfg.DNS.Port)
	}

	// 创建API服务
	apiServer := api.NewAPI(cfg, *dbPath, dnsServer, blockList, &staticFiles, log)

	// 启动API服务器
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Fatalf("启动API服务器失败: %v", err)
		}
	}()
	log.Infof("API服务已启动在端口 %d", cfg.API.Port)

	// 服务启动完成后，异步加载黑名单
	go func() {
		log.Info("开始异步加载黑名单...")
		if err := blockList.Update(); err != nil {
			log.Errorf("加载黑名单失败: %v", err)
		} else {
			log.Infof("黑名单加载完成，共 %d 条广告域名记录", blockList.GetDomainsCount())
		}
	}()

	// 等待中断信号停止服务
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info("正在关闭服务...")
	if err := dnsServer.Stop(); err != nil {
		log.Errorf("关闭DNS服务器出错: %v", err)
	}

	// 关闭数据库连接
	if err := config.Close(); err != nil {
		log.Errorf("关闭数据库连接出错: %v", err)
	}

	log.Info("服务已停止")
}
