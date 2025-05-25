# Python HTTP Server : 西安交通大学 计算机网络专题实验

一个功能完整的HTTP/HTTPS Web服务器实现，基于Python Socket编程构建，支持多种HTTP特性和高级功能。

## 功能特性

### 基础HTTP功能
-  **HTTP方法支持**: GET、HEAD、POST
-  **URI编码**: 支持"%HEXHEX"编码格式处理
-  **状态码**: 完整的HTTP状态码支持（200、304、100、404、401、403、417、501、500等）
-  **连接管理**: 支持Keep-Alive和Close连接模式

### 高级特性
-  **HTTPS支持**: SSL/TLS加密连接
-  **分块传输**: Chunked Transfer Encoding支持
-  **内容压缩**: GZIP压缩支持
-  **Cookie管理**: 基于RFC 2109的Cookie机制
-  **缓存处理**: HTTP缓存控制（Cache-Control, ETag, Last-Modified）
-  **文件上传**: 基于POST的multipart/form-data文件上传

### 服务器特性
-  **可配置**: 监听地址、端口、虚拟路径可配置
-  **多线程**: 并发请求处理
-  **日志记录**: 详细的访问日志和错误日志
-  **用户认证**: 基于Session的登录系统
-  **CGI支持**: Common Gateway Interface支持

## 快速开始

### 环境要求
- Python 3.6+
- 标准库依赖（无需额外安装）

### 安装运行

1. **克隆仓库**
```bash
git clone https://github.com/yuyueryuyu/XJTU_NetworkLab.git
cd XJTU_NetworkLab
```

2. **创建www目录和必要文件**
```bash
mkdir www
mkdir www/cgi_bin
```
仓库下也存放了测试基础功能的./www目录，如果需要的话，可以使用它进行测试。

3. **创建SSL证书（HTTPS功能）**
```bash
mkdir .ssh
# 生成自签名证书
openssl req -x509 -newkey rsa:4096 -keyout .ssh/localhost+2-key.pem -out .ssh/localhost+2.pem -days 365 -nodes
```

4. **配置未授权页面**
```bash
cd www
vim login.html
# 创建login.html
```
或者直接修改相关方法
```python
def unauthorized_response(self, request):
    '''
    给未授权用户返回登录页面+401 Unauthorized的方法
    '''
    try:
        return self.serve_file(
            os.path.normpath(os.path.join(self.root, 'login.html'.lstrip('/'))), 
            request, include_body=True, 
            intended_code=401, intended_msg="Unauthorized"
        )
    except NetworkError as e:
        return self.error_response(401, "Unauthorized")

```


5. **启动服务器**
```bash
sudo python3 http_server.py
```

服务器将在以下端口启动：
- HTTP: `http://localhost:8080`
- HTTPS: `https://localhost:8443`

## 使用指南

### 基本配置

在`http_server.py`中修改配置：

```python
# HTTP服务器配置
http_server = set_server('0.0.0.0', 8080, logger)

# HTTPS服务器配置
https_server = set_server('0.0.0.0', 8443, logger,
    "./.ssh/localhost+2.pem", "./.ssh/localhost+2-key.pem")
```

### 文件结构

```
project/
├── server.py              # 主服务器文件
├── www/                   # Web根目录
│   ├── index.html         # 默认首页
│   ├── login.html         # 登录页面
│   ├── cgi_bin/          # CGI脚本目录
│   └── server_log.log    # 服务器日志
└── .ssh/                 # SSL证书目录
    ├── localhost+2.pem
    └── localhost+2-key.pem
```

### 登录认证

默认登录凭据：
- 用户名: `admin`
- 密码: `secret`

### CGI脚本示例

在`www/cgi_bin/`目录下创建Python CGI脚本：

```python
#!/usr/bin/env python3
import os

print("Content-Type: text/html")
print()

print("<html><body>")
print(f"<h1>CGI Test</h1>")
print(f"<p>Method: {os.environ.get('REQUEST_METHOD')}</p>")
print(f"<p>Remote Address: {os.environ.get('REMOTE_ADDR')}</p>")
print("</body></html>")
```

## API接口

### HTTP方法

| 方法 | 描述 | 示例 |
|------|------|------|
| GET | 获取资源 | `GET /index.html` |
| HEAD | 获取资源头信息 | `HEAD /index.html` |
| POST | 提交数据 | `POST /login` |

### 状态码

| 状态码 | 描述 |
|--------|------|
| 200 | OK - 请求成功 |
| 304 | Not Modified - 资源未修改 |
| 100 | Continue - 继续请求 |
| 400 | Bad Request - 请求错误 |
| 401 | Unauthorized - 未授权 |
| 403 | Forbidden - 禁止访问 |
| 404 | Not Found - 资源不存在 |
| 417 | Expectation Failed - 期望失败 |
| 500 | Internal Server Error - 服务器内部错误 |
| 501 | Not Implemented - 方法未实现 |

### 浏览器测试

直接在浏览器中访问：
- `http://localhost:8080` - HTTP服务
- `https://localhost:8443` - HTTPS服务（需要接受自签名证书警告）

## 📊 日志系统

服务器会在`www/server_log.log`中记录：
- 客户端IP地址和端口
- HTTP请求方法和路径
- User-Agent信息
- 响应状态码
- 错误信息


## 安全特性

- **路径验证**: 防止目录遍历攻击
- **输入验证**: 请求头和内容验证
- **会话管理**: 安全的Session机制
- **HTTPS加密**: SSL/TLS支持
- **权限控制**: 基于登录的访问控制

## 技术实现

- **Socket编程**: 底层网络通信
- **多线程**: `threading`模块实现并发
- **SSL/TLS**: `ssl`模块提供加密支持
- **压缩**: `zlib`模块实现GZIP压缩
- **CGI**: `subprocess`模块执行外部脚本

### 架构设计
- **WebServer类**: 主服务器类，处理连接和请求
- **NetworkError类**: 自定义异常处理
- **模块化设计**: 功能分离，便于维护和扩展

## 参考文档

- [RFC 2616](https://tools.ietf.org/html/rfc2616) - HTTP/1.1
- [RFC 6265](https://tools.ietf.org/html/rfc6265) - HTTP State Management (Cookies)
- [RFC 3875](https://tools.ietf.org/html/rfc3875) - Common Gateway Interface (CGI)
- [RFC 2109](https://tools.ietf.org/html/rfc2109) - HTTP State Management Mechanism
