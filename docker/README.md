# Docker 部署说明

## 文件结构

```
docker/
├── Dockerfile.frontend    # 前端镜像（Nginx + React）
├── Dockerfile.backend     # 后端镜像（FastAPI + Selenium）
├── docker-compose.yml     # 容器编排配置
├── nginx.conf             # Nginx 配置
├── Dockerfile.legacy      # 旧版单体部署（仅供参考）
└── README.md              # 本文件
```

## 快速开始

### 使用 Docker Compose 部署

```bash
cd docker
docker-compose up -d --build
```

### 访问服务

- 前端: http://localhost
- 后端 API: http://localhost:4500
- API 文档: http://localhost:4500/docs

### 停止服务

```bash
cd docker
docker-compose down
```

## 镜像说明

### 前端镜像 (`Dockerfile.frontend`)

- 基于 Node.js 20 构建 React 应用
- 使用 Nginx 作为静态文件服务器
- 自动代理 API 请求到后端

### 后端镜像 (`Dockerfile.backend`)

- 基于 Python 3.10
- 包含 Chromium 和 ChromeDriver（用于保活功能）
- 暴露端口 4500

## 环境变量

后端支持以下环境变量：

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `CORS_ORIGINS` | 允许的跨域来源 | `http://localhost,http://localhost:80,http://frontend` |
| `HTTP_PROXY` | HTTP 代理 | - |
| `HTTPS_PROXY` | HTTPS 代理 | - |

## 数据持久化

`docker-compose.yml` 配置了以下数据卷：

- `gemini-data`: 数据库文件
- `gemini-images`: 生成的图片

## GitHub Actions

项目配置了自动构建和推送镜像到 Docker Hub：

- 推送到 `main` 分支：构建并推送 `latest` 标签
- 推送 `v*` 标签：构建并推送对应版本标签

镜像地址：
- `qxdljy/gemini-link-frontend`
- `qxdljy/gemini-link-backend`
