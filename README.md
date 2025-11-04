# Gin DNS

一个基于Gin框架的DNS over TLS (DoT) 服务，用于为安卓手机提供去广告的私有DNS服务。

## 功能特点

- 支持DNS over TLS (DoT)，适用于安卓9+系统的私有DNS
- 广告域名拦截和缓存
- 可配置上游DNS服务器
- 域名白名单管理
- 完整的监控和统计功能
- RESTful API管理接口

## 安装和使用

### 前提条件

- Go 1.16+
- 有效的SSL证书（用于DoT服务）

### 安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/gin_dns.git

# 进入项目目录
cd gin_dns

# 安装依赖
go mod download

# 构建项目
go build -o gin_dns
```

### 运行

首次运行时，会在当前目录创建默认配置文件`config.yaml`：

```bash
./gin_dns
```

可以指定配置文件路径：

```bash
./gin_dns --config=/path/to/config.yaml
```

设置日志级别：

```bash
./gin_dns --log-level=debug
```

## SSL证书

对于DoT服务，需要有效的SSL证书。可以使用Let's Encrypt获取免费的证书，或使用自签名证书进行测试。


## 在安卓设备上使用

1. 确保您有一个有效的域名和SSL证书
2. 在服务器上运行gin_dns
3. 在安卓设备上：
   - 设置 > 网络和互联网 > 私人DNS
   - 选择"私人DNS提供商主机名"
   - 输入您的域名（如`dns.example.com`）

## 许可证

MIT
