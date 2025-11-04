package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/yuxy/gin_dns/config"
	"golang.org/x/crypto/bcrypt"
)

// Claims JWT声明结构
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// LoginRequest 登录请求结构
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse 登录响应结构
type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ChangePasswordRequest 修改密码请求结构
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// hashPassword 使用bcrypt加密密码
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// verifyPassword 验证密码是否匹配
func verifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// generateToken 生成JWT token
func (a *API) generateToken(username string) (string, time.Time, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // token有效期24小时
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "gin_dns",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(a.config.API.JWTSecret))
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expirationTime, nil
}

// JWTAuthMiddleware JWT认证中间件
func (a *API) JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少Authorization header"})
			c.Abort()
			return
		}

		// 检查Bearer前缀
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header格式错误，应为: Bearer {token}"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// 解析token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(a.config.API.JWTSecret), nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的token签名"})
				c.Abort()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token解析失败: " + err.Error()})
			c.Abort()
			return
		}

		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token无效或已过期"})
			c.Abort()
			return
		}

		// 将用户信息存储到上下文中
		c.Set("username", claims.Username)
		c.Next()
	}
}

// login 登录处理程序
func (a *API) login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求格式: " + err.Error()})
		return
	}

	// 验证用户名
	if req.Username != a.config.Auth.Username {
		a.log.Warnf("登录失败: 用户名错误 (尝试用户名: %s)", req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 验证密码（使用bcrypt）
	if err := verifyPassword(a.config.Auth.Password, req.Password); err != nil {
		a.log.Warnf("登录失败: 密码错误 (用户名: %s)", req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 生成token
	token, expiresAt, err := a.generateToken(req.Username)
	if err != nil {
		a.log.Errorf("生成token失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成token失败"})
		return
	}

	a.log.Infof("用户 %s 登录成功", req.Username)
	c.JSON(http.StatusOK, LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
	})
}

// changePassword 修改密码处理程序
func (a *API) changePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求格式: " + err.Error()})
		return
	}

	// 验证旧密码（使用bcrypt）
	if err := verifyPassword(a.config.Auth.Password, req.OldPassword); err != nil {
		a.log.Warnf("修改密码失败: 旧密码错误")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "旧密码错误"})
		return
	}

	// 验证新密码强度（至少6个字符）
	if len(req.NewPassword) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "新密码长度至少为6个字符"})
		return
	}

	// 加密新密码
	hashedPassword, err := hashPassword(req.NewPassword)
	if err != nil {
		a.log.Errorf("加密密码失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "加密密码失败"})
		return
	}

	// 更新密码
	a.config.Auth.Password = hashedPassword
	if err := config.SaveConfig(a.dbPath, a.config); err != nil {
		a.log.Errorf("保存配置到数据库失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存配置到数据库失败: " + err.Error()})
		return
	}

	username, _ := c.Get("username")
	a.log.Infof("用户 %s 修改密码成功", username)
	c.JSON(http.StatusOK, gin.H{"status": "密码修改成功，请使用新密码重新登录"})
}
