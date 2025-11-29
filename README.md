# Gemini Link System

一个将 Gemini Business API 转换为 OpenAI 兼容接口的网关服务，支持多账号负载均衡、API 密钥管理、图片生成和思考过程显示等功能。

<div align="center">

  <img width="642" height="540" alt="78e0edf7-a521-483e-bfc8-2e185594ea66" src="https://github.com/user-attachments/assets/20dccf7f-6dc0-446e-b57e-d492448f979c" />

</div>

<div align="center">

  <img width="593" height="532" alt="f49c2af4-2036-4895-a50f-b665b51cf33a" src="https://github.com/user-attachments/assets/69d44114-cac5-4e65-a52f-b01ec6333a7c" />

</div>

<div align="center">

  <img width="622" height="484" alt="8c87f393-b3f1-4eec-8059-e040487e28ee" src="https://github.com/user-attachments/assets/566a1872-837f-43eb-a05f-6dfe8e6e885f" />

</div>

<div align="center">

  <img width="1912" height="954" alt="3aabf85c-6dd8-4626-a574-001ab30003ec" src="https://github.com/user-attachments/assets/25230990-cebb-41e7-8a7f-a54f8873ad61" />

</div>

<div align="center">

  <img width="868" height="725" alt="7921b683-ef14-4d9b-9213-9285bdd641bf" src="https://github.com/user-attachments/assets/452270c8-4273-4cea-be7b-f0f66ba5e2d5" />

</div>

<div align="center">

  <img width="869" height="792" alt="706362b2-9e7d-4097-a412-768bbcc8d1dc" src="https://github.com/user-attachments/assets/45018700-ab40-481b-9b52-279a12c48a49" />

</div>

## ✨ 功能特性

- 🚀 **OpenAI 兼容接口**：完全兼容 OpenAI Chat Completions API
- 🔑 **API 密钥管理**：支持生成、管理和撤销 API 密钥
- 📊 **使用统计**：详细的 API 调用日志和统计信息
- 🖼️ **图片生成**：支持 Gemini 图片生成输入功能，自动下载和保存
- 💭 **思考过程显示**：支持显示模型的思考过程（可折叠）
- 🔄 **多账号支持**：支持配置多个 Gemini Business 账号，自动负载均衡
- 🛡️ **账号容错**：自动检测账号配额限制，切换到备用账号
- 📝 **管理员面板**：Web 界面管理 API 密钥和查看统计
- ⚙️ **账号管理**：可视化界面管理 Gemini Business 账号配置，支持添加、编辑、测试和删除

## 📋 系统要求

- Docker（推荐，无需额外安装 Python 环境）
- 或 Python 3.10+（本地开发/运行）
- SQLite（默认）或 PostgreSQL
- Gemini Business 账号凭证

## 🚀 快速开始（Docker 推荐）

### 1. 拉取 Docker 镜像

直接从 Docker Hub 拉取最新镜像（无需手动构建）：

```bash
docker pull qxdljy/gemini-link-system:latest
```

### 2. 准备环境文件（必填）

#### 2.1 创建环境变量文件

在本地创建 `.env` 文件（建议单独创建一个文件夹存放，如 `gemini-link-system`），内容参考以下配置：

```env
# 单账号配置（必填，二选一）
SECURE_C_SES=your_secure_c_ses_value
CSESIDX=your_csesidx_value
CONFIG_ID=your_config_id_value
HOST_C_OSES=your_host_c_oses_value  # 可选

# 或 多账号配置（推荐，自动负载均衡）
# ACCOUNT1_SECURE_C_SES=your_secure_c_ses_1
# ACCOUNT1_CSESIDX=your_csesidx_1
# ACCOUNT1_CONFIG_ID=your_config_id_1
# ACCOUNT1_NAME=account-1  # 可选
# ACCOUNT2_SECURE_C_SES=your_secure_c_ses_2
# ACCOUNT2_CSESIDX=your_csesidx_2
# ACCOUNT2_CONFIG_ID=your_config_id_2

# 可选配置
PROXY=http://proxy.example.com:7890  # 代理设置（如需）
TIMEOUT_SECONDS=600  # 请求超时时间（默认 600 秒）
```

#### 2.2 填写配置说明

- 从 Gemini Business 账号中获取 `SECURE_C_SES`、`CSESIDX`、`CONFIG_ID` 等核心凭证
- 多账号配置时，只需按 `ACCOUNTn_*` 格式递增添加即可，系统会自动负载均衡

### 3. 准备数据目录（可选，实现数据持久化）

为避免容器重启后数据丢失（如 API 密钥、调用日志、生成的图片），建议挂载本地目录到容器：

#### 3.1 创建本地目录

在 `.env` 文件所在目录，创建两个文件夹：

```bash
# Linux/macOS
mkdir -p geminibusiness.db generated_images

# Windows（CMD）
mkdir geminibusiness.db generated_images

# Windows（PowerShell）
New-Item -ItemType Directory -Path geminibusiness.db, generated_images
```

- `geminibusiness.db`：存储 SQLite 数据库文件（自动生成）
- `generated_images`：存储生成的图片文件（自动下载）

### 4. 运行 Docker 容器

根据操作系统选择对应的命令，确保命令在 `.env` 文件所在目录执行：

#### 4.1 Linux/macOS（Bash/Zsh）

```bash
docker run -d \
  --name gemini-link-system \
  -p 5000:5000 \
  --env-file .env \
  -v $(pwd)/geminibusiness.db:/app/geminibusiness.db \
  -v $(pwd)/generated_images:/app/generated_images \
  qxdljy/gemini-link-system:latest
```

#### 4.2 Windows（PowerShell）

```powershell
docker run -d `
  --name gemini-link-system `
  -p 5000:5000 `
  --env-file .env `
  -v ${PWD}/geminibusiness.db:/app/geminibusiness.db `
  -v ${PWD}/generated_images:/app/generated_images `
  qxdljy/gemini-link-system:latest
```

#### 4.3 Windows（CMD）

```cmd
docker run -d ^
--name gemini-link-system ^
-p 5000:5000 ^
--env-file .env ^
-v %cd%\geminibusiness.db:/app/geminibusiness.db ^
-v %cd%\generated_images:/app/generated_images ^
qxdljy/gemini-link-system:latest
```

#### 4.4 命令说明

- `-d`：后台运行容器
- `--name`：容器名称（可自定义）
- `-p 5000:5000`：端口映射（本地端口:容器端口）
- `--env-file .env`：加载环境变量配置
- `-v`：挂载本地目录到容器（实现数据持久化）

### 5. 验证服务启动

容器启动后，访问以下地址确认服务正常：

- 管理面板：`http://localhost:5000/static/index.html`
- API 接口地址：`http://localhost:5000/v1`

## 🔧 基础配置与使用

### 1. 登录管理面板

1. 访问 `http://localhost:5000/static/index.html`
2. 默认管理员账号：
   - 用户名：`admin`
   - 密码：`admin123456`
3. **⚠️ 生产环境请立即修改默认密码！**

### 2. 生成 API 密钥

1. 登录管理面板后，进入「API 密钥管理」页面
2. 点击「生成新密钥」，设置密钥名称和过期时间
3. 复制生成的 API 密钥（仅显示一次，妥善保存）

### 3. 支持的模型

服务默认支持以下模型，调用时直接指定即可：

- `gemini-auto` - 自动选择最优模型
- `gemini-2.5-flash` - 快速响应模型（适合日常对话）
- `gemini-2.5-pro` - 平衡推理模型（适合复杂任务）
- `gemini-3-pro-preview` - 预览版旗舰模型（支持图片生成）

### 4. 账号管理

在管理面板中，点击「账号管理」按钮可以进入账号配置页面，支持以下功能：

- **查看账号列表**：显示所有已配置的 Gemini Business 账号及其状态（可用/不可用）
- **添加账号**：通过 Web 界面添加新的账号配置，无需手动编辑 `.env` 文件
- **编辑账号**：修改现有账号的配置信息（名称、SECURE_C_SES、CSESIDX、CONFIG_ID 等）
- **测试账号**：一键测试账号是否可用，验证 JWT 获取是否正常
- **删除账号**：删除不再使用的账号配置

**重要提示**：
- 修改账号配置后需要重启服务才能生效
- 建议在修改前备份 `.env` 文件
- 系统会自动将旧格式账号（`SECURE_C_SES`、`CSESIDX` 等）转换为新格式（`ACCOUNTn_*`）

## 📖 API 使用示例

### 1. Python 调用（兼容 OpenAI 逻辑）

```python
import requests

# 基础配置
API_KEY = "你的生成的 API 密钥"
BASE_URL = "http://localhost:5000/v1"

# 对话请求（流式输出）
url = f"{BASE_URL}/chat/completions"
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}
data = {
    "model": "gemini-3-pro-preview",
    "messages": [{"role": "user", "content": "你好，请介绍一下自己"}],
    "stream": True
}

# 发送请求并处理流式响应
response = requests.post(url, headers=headers, json=data, stream=True)
for line in response.iter_lines():
    if line:
        chunk = line.decode("utf-8").lstrip("data: ").strip()
        if chunk != "[DONE]":
            import json
            print(json.loads(chunk)["choices"][0]["delta"].get("content", ""), end="")
```

### 2. OpenAI SDK 直接调用

```python
from openai import OpenAI

# 初始化客户端（指定网关地址）
client = OpenAI(
    api_key="你的生成的 API 密钥",
    base_url="http://localhost:5000/v1"
)

# 图片生成示例（非流式）
response = client.chat.completions.create(
    model="gemini-3-pro-preview",
    messages=[{"role": "user", "content": "生成一张人工智能主题的图片，未来科技风格"}],
    stream=False
)

# 提取图片信息（base64 或文件路径）
if hasattr(response, 'images'):
    for img in response.images:
        print(f"图片文件名：{img['file_name']}")
        print(f"图片保存路径：generated_images/{img['file_name']}")
        print(f"base64 编码（前 100 字符）：{img['base64'][:100]}...")
```

### 3. cURL 命令调用

```bash
curl -X POST http://localhost:5000/v1/chat/completions \
  -H "Authorization: Bearer 你的生成的 API 密钥" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-2.5-flash",
    "messages": [{"role": "user", "content": "解释什么是人工智能"}],
    "stream": true
  }'
```

## 🖼️ 图片生成功能说明

1. 仅 `gemini-3-pro-preview` 模型支持图片生成
2. 生成的图片会自动保存到本地 `generated_images` 目录（通过挂载实现）
3. API 响应中会包含图片的 `base64` 编码和文件名，可直接用于前端展示
4. 支持 Markdown 格式输出（如 `![图片描述](data:image/png;base64,...)`）

## 💭 思考过程显示

服务会自动提取模型的思考过程，默认以可折叠格式返回：

- 流式响应中，思考过程会随内容一起输出
- 非流式响应中，思考过程包含在 `thinking` 字段中
- 管理面板中可查看完整的思考步骤日志

## ⚙️ 账号管理功能

系统提供了完整的 Web 界面来管理 Gemini Business 账号配置，无需手动编辑 `.env` 文件。

### 功能特性

- **可视化界面**：直观的表格展示所有已配置账号及其状态
- **账号状态显示**：实时显示账号可用状态（可用/不可用/未知）
- **添加账号**：通过表单添加新账号，自动分配索引号
- **编辑账号**：修改账号配置信息（名称、凭证等）
- **测试账号**：一键测试账号连通性和 JWT 获取能力
- **删除账号**：安全删除不再使用的账号配置
- **自动转换**：旧格式账号（`SECURE_C_SES` 等）自动转换为新格式（`ACCOUNTn_*`）

### 使用方法

1. 登录管理面板后，点击右上角「账号管理」按钮
2. 在账号列表页面可以：
   - 点击「添加账号」创建新账号配置
   - 点击「测试」验证账号是否可用
   - 点击「编辑」修改账号信息
   - 点击「删除」移除账号（需确认）

### 注意事项

- ⚠️ **修改配置后需重启服务**：所有账号配置修改都会写入 `.env` 文件，需要重启容器/服务才能生效
- 💾 **建议备份**：修改前请备份 `.env` 文件，避免配置丢失
- 🔄 **自动负载均衡**：多账号配置后，系统会自动在可用账号间进行负载均衡

## 🐳 Docker Compose 部署（推荐生产环境）

如果需要更灵活的配置（如自定义端口、日志轮转），可使用 `docker-compose.yml`：

### 1. 创建 docker-compose.yml 文件

```yaml
version: '3.8'

services:
  gemini-link-system:
    image: qxdljy/gemini-link-system:latest
    container_name: gemini-link-system
    restart: always  # 容器异常时自动重启
    ports:
      - "5000:5000"  # 可修改左侧本地端口（如 8080:5000）
    env_file:
      - .env  # 引用环境变量文件
    volumes:
      - ./geminibusiness.db:/app/geminibusiness.db
      - ./generated_images:/app/generated_images
    logging:
      driver: "json-file"
      options:
        max-size: "10m"  # 单日志文件最大 10MB
        max-file: "3"    # 最多保留 3 个日志文件
```

### 2. 启动服务

```bash
# 启动（后台运行）
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down

# 停止并删除数据卷（谨慎使用）
docker-compose down -v
```

## 🔐 安全建议

1. **修改默认密码**：首次登录管理面板后，立即在「个人设置」中修改管理员密码
2. **API 密钥管理**：为不同应用分配独立的 API 密钥，定期轮换并撤销无用密钥
3. **环境变量保护**：不要将 `.env` 文件提交到版本控制，避免泄露账号凭证
4. **端口限制**：生产环境建议通过防火墙限制 5000 端口的访问范围（仅允许信任的 IP）
5. **HTTPS 配置**：通过 Nginx 等反向代理配置 HTTPS，加密传输数据

## 🐛 故障排除

### 1. 容器启动失败

- 检查 `.env` 文件格式是否正确（无语法错误、无多余空格）
- 确认 Gemini 账号凭证是否有效（可登录 Gemini Business 后台验证）
- 查看容器日志：`docker logs gemini-link-system`

### 2. 无法访问管理面板

- 检查容器是否正常运行：`docker ps | grep gemini-link-system`
- 确认端口映射正确（无端口冲突）：`netstat -tuln | grep 5000`（Linux/macOS）
- 检查本地防火墙是否阻止了 5000 端口

### 3. 图片生成失败

- 确认使用的模型是 `gemini-3-pro-preview`
- 检查 `generated_images` 目录权限（是否可写）
- 查看日志中的错误信息，确认账号是否有图片生成权限

## 🛠️ 开发者教程（本地构建与开发）

以下步骤适用于需要二次开发或本地调试的开发者：

### 1. 克隆项目代码

```bash
git clone https://github.com/qxd-ljy/Gemini-Link-System.git
cd Gemini-Link-System  # 注意：原命令有笔误（gGemini-Link-System → Gemini-Link-System）
```

### 2. 安装依赖

```bash
# 创建虚拟环境（可选但推荐）
python -m venv venv

# 激活虚拟环境
# Linux/macOS：source venv/bin/activate
# Windows（CMD）：venv\Scripts\activate.bat
# Windows（PowerShell）：.\venv\Scripts\Activate.ps1

# 安装依赖
pip install -r requirements.txt
```

### 3. 配置环境变量

```bash
# 复制示例文件
cp .env.example .env

# 编辑 .env 文件，填写 Gemini 账号信息
```

### 4. 本地运行服务

```bash
# 开发模式（自动重载）
uvicorn main:app --reload --host 0.0.0.0 --port 5000

# 或直接运行
python main.py
```

### 5. 本地构建 Docker 镜像

```bash
# 构建镜像
docker build -t gemini-link-system:local .

# 运行本地构建的镜像
docker run -d \
  --name gemini-link-system-local \
  -p 5000:5000 \
  --env-file .env \
  -v $(pwd)/geminibusiness.db:/app/geminibusiness.db \
  -v $(pwd)/generated_images:/app/generated_images \
  gemini-link-system:local
```

### 6. 项目结构说明

```
Gemini-Link-System/
├── main.py                 # 主应用入口（FastAPI 初始化、路由注册）
├── auth.py                 # 认证模块（API 密钥验证、JWT 处理）
├── database.py             # 数据库模型（SQLAlchemy 配置、数据模型）
├── gemini_api.py           # Gemini Business API 调用逻辑
├── requirements.txt        # Python 依赖清单
├── Dockerfile              # Docker 镜像构建配置
├── docker-compose.yml      # Docker Compose 配置
├── .env.example            # 环境变量示例文件
├── static/                 # 管理面板静态文件（HTML/CSS/JS）
│   ├── index.html          # 登录页
│   ├── dashboard.html      # 管理面板主页（API 密钥管理）
│   ├── accounts.html       # 账号管理页面
│   ├── style.css           # 样式文件
│   └── app.js              # 前端交互逻辑
├── geminibusiness.db       # SQLite 数据库（自动生成）
└── generated_images/       # 图片生成目录（自动创建）
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！贡献流程：

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feature/xxx`
3. 提交修改：`git commit -m "feat: 添加 xxx 功能"`
4. 推送分支：`git push origin feature/xxx`
5. 提交 Pull Request

## 📄 许可证

本项目采用 MIT 许可证。

## 🙏 致谢

- [FastAPI](https://fastapi.tiangolo.com/) - 现代、快速的 Web 框架
- [Gemini Business](https://business.gemini.google/) - Google 的 Gemini Business API
- [Docker](https://www.docker.com/) - 容器化部署工具
- [SQLAlchemy](https://www.sqlalchemy.org/) - Python ORM 框架

## 📞 支持

如有问题或建议，请提交 [Issue](https://github.com/qxd-ljy/Gemini-Link-System/issues)。
