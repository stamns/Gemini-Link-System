
"""
数据库模型和配置
"""
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# 北京时间 UTC+8
BEIJING_TZ = timezone(timedelta(hours=8))

def get_beijing_time():
    """获取当前北京时间（naive，用于数据库存储）"""
    return datetime.now(BEIJING_TZ).replace(tzinfo=None)

# SQLite 数据库
DATABASE_URL = "sqlite:///./geminibusiness.db"

engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Admin(Base):
    """管理员账号表"""
    __tablename__ = "admins"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    hashed_password = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=get_beijing_time)


class APIKey(Base):
    """API 密钥表"""
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String(100), unique=True, nullable=False, index=True)
    encrypted_key = Column(String(200), nullable=False)  # 存储加密后的密钥
    name = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=get_beijing_time)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    usage_count = Column(Integer, default=0)
    last_used_at = Column(DateTime, nullable=True)


class APICallLog(Base):
    """API 调用日志表"""
    __tablename__ = "api_call_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, nullable=False, index=True)  # 关联的 API Key ID
    timestamp = Column(DateTime, default=get_beijing_time, index=True)  # 调用时间
    model = Column(String(50), nullable=True)  # 使用的模型
    status = Column(String(20), nullable=False)  # success 或 error
    error_message = Column(String(500), nullable=True)  # 错误信息
    ip_address = Column(String(50), nullable=True)  # 客户端 IP
    endpoint = Column(String(100), nullable=True)  # 调用的端点
    response_time = Column(Integer, nullable=True)  # 响应时间（毫秒）


class KeepAliveTask(Base):
    """保活任务表"""
    __tablename__ = "keep_alive_tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    is_enabled = Column(Boolean, default=True)  # 是否启用
    schedule_time = Column(String(10), default="00:00")  # 执行时间（HH:MM格式，北京时间）
    last_run_at = Column(DateTime, nullable=True)  # 上次执行时间
    last_status = Column(String(20), nullable=True)  # 上次执行状态：success, error, running
    last_message = Column(String(500), nullable=True)  # 上次执行消息
    created_at = Column(DateTime, default=get_beijing_time)
    updated_at = Column(DateTime, default=get_beijing_time, onupdate=get_beijing_time)


class KeepAliveLog(Base):
    """保活任务执行日志表"""
    __tablename__ = "keep_alive_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, nullable=False, index=True)  # 关联的任务ID
    started_at = Column(DateTime, default=get_beijing_time, index=True)  # 开始时间
    finished_at = Column(DateTime, nullable=True)  # 结束时间
    status = Column(String(20), nullable=False)  # success, error, running, cancelled
    message = Column(String(1000), nullable=True)  # 执行消息
    accounts_count = Column(Integer, nullable=True)  # 处理的账号数量
    success_count = Column(Integer, nullable=True)  # 成功数量
    fail_count = Column(Integer, nullable=True)  # 失败数量


class KeepAliveAccountLog(Base):
    """保活账号级别日志表"""
    __tablename__ = "keep_alive_account_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    task_log_id = Column(Integer, nullable=False, index=True)  # 关联的任务日志ID
    account_name = Column(String(200), nullable=False)  # 账号名称
    account_email = Column(String(200), nullable=True)  # 账号邮箱
    started_at = Column(DateTime, default=get_beijing_time, index=True)  # 开始时间
    finished_at = Column(DateTime, nullable=True)  # 结束时间
    status = Column(String(20), nullable=False)  # success, error, running, cancelled
    message = Column(String(500), nullable=True)  # 执行消息


def init_db():
    """初始化数据库表"""
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    """获取数据库会话"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
