import { useState, useEffect, useCallback, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { api, formatDate, formatShortDate, getKeyStatus, copyToClipboard, wsManager } from '../api/client';
import type { Stats, APIKey, KeyStats, CallLog } from '../api/types';

// 图标组件
const KeyIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path>
  </svg>
);

const CheckCircleIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
    <polyline points="22 4 12 14.01 9 11.01"></polyline>
  </svg>
);

const ChartIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="20" x2="18" y2="10"></line>
    <line x1="12" y1="20" x2="12" y2="4"></line>
    <line x1="6" y1="20" x2="6" y2="14"></line>
  </svg>
);

export default function Dashboard() {
  // 状态
  const [stats, setStats] = useState<Stats>({ active_keys: 0, total_usage: 0 });
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [selectedKeys, setSelectedKeys] = useState<Set<number>>(new Set());
  const [isLoading, setIsLoading] = useState(true);
  
  // 生成密钥表单
  const [generateForm, setGenerateForm] = useState({
    count: 1,
    expiresDays: 30,
    namePrefix: 'API Key',
  });
  
  // 模态框状态
  const [generatedKeys, setGeneratedKeys] = useState<APIKey[]>([]);
  const [showKeysModal, setShowKeysModal] = useState(false);
  const [showLogsModal, setShowLogsModal] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [showKeepAliveModal, setShowKeepAliveModal] = useState(false);
  
  // 日志相关
  const [currentKeyId, setCurrentKeyId] = useState<number | null>(null);
  const [currentKeyName, setCurrentKeyName] = useState('');
  const [keyStats, setKeyStats] = useState<KeyStats | null>(null);
  const [logs, setLogs] = useState<CallLog[]>([]);
  const [logsPage, setLogsPage] = useState(1);
  const [logsTotal, setLogsTotal] = useState(0);

  // 加载统计
  const loadStats = useCallback(async () => {
    try {
      const data = await api.getStats();
      setStats(data);
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  }, []);

  // 加载密钥列表
  const loadKeys = useCallback(async () => {
    try {
      const data = await api.getAPIKeys();
      setKeys(data);
    } catch (error) {
      console.error('Failed to load keys:', error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // 加载日志
  const loadKeyLogs = useCallback(async (keyId: number, page: number = 1) => {
    try {
      const data = await api.getKeyLogs(keyId, page, 20);
      setLogs(data.logs);
      setLogsPage(data.page);
      setLogsTotal(Math.ceil(data.total / data.page_size));
    } catch (error) {
      console.error('Failed to load logs:', error);
    }
  }, []);

  // 初始化
  useEffect(() => {
    loadStats();
    loadKeys();

    // WebSocket 连接
    wsManager.connect((data) => {
      if (data === 'update') {
        loadStats();
        if (selectedKeys.size === 0) {
          loadKeys();
        }
      }
    });

    return () => {
      wsManager.disconnect();
    };
  }, [loadStats, loadKeys, selectedKeys.size]);

  // 登出
  const handleLogout = () => {
    api.logout();
  };

  // 生成密钥
  const handleGenerateKeys = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const newKeys = await api.generateAPIKeys({
        count: generateForm.count,
        expires_days: generateForm.expiresDays,
        name_prefix: generateForm.namePrefix,
      });
      setGeneratedKeys(newKeys);
      setShowKeysModal(true);
      loadStats();
      loadKeys();
      setGenerateForm({ count: 1, expiresDays: 30, namePrefix: 'API Key' });
    } catch (error) {
      alert('生成密钥失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  // 复制单个密钥
  const handleCopyKey = async (key: string) => {
    const success = await copyToClipboard(key);
    if (success) {
      alert('密钥已复制到剪贴板');
    } else {
      alert('复制失败，请手动复制:\n' + key);
    }
  };

  // 复制所有密钥
  const handleCopyAllKeys = async () => {
    const allKeys = generatedKeys.map(k => k.key).join('\n');
    const success = await copyToClipboard(allKeys);
    if (success) {
      alert('所有密钥已复制到剪贴板');
    } else {
      alert('复制失败，请手动复制:\n' + allKeys);
    }
  };

  // 查看并复制密钥
  const handleViewAndCopyKey = async (keyId: number) => {
    try {
      const data = await api.viewAPIKey(keyId);
      const success = await copyToClipboard(data.key);
      if (success) {
        alert(`密钥已复制到剪贴板:\n${data.key}`);
      } else {
        alert('请手动复制密钥:\n' + data.key);
      }
    } catch (error) {
      alert('获取密钥失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  // 查看调用日志
  const handleViewKeyLogs = async (keyId: number, keyName: string) => {
    setCurrentKeyId(keyId);
    setCurrentKeyName(keyName);
    setShowLogsModal(true);
    setKeyStats(null);
    setLogs([]);

    try {
      const statsData = await api.getKeyStats(keyId);
      setKeyStats(statsData);
      await loadKeyLogs(keyId, 1);
    } catch (error) {
      alert('加载调用详情失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  // 撤销密钥
  const handleRevokeKey = async (keyId: number) => {
    if (!confirm('确定要撤销这个密钥吗？此操作不可逆！')) {
      return;
    }
    try {
      await api.revokeAPIKey(keyId);
      alert('密钥已撤销');
      loadStats();
      loadKeys();
    } catch (error) {
      alert('撤销失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  // 全选/取消全选
  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedKeys(new Set(keys.map(k => k.id)));
    } else {
      setSelectedKeys(new Set());
    }
  };

  // 选择单个
  const handleSelectKey = (keyId: number, checked: boolean) => {
    const newSelected = new Set(selectedKeys);
    if (checked) {
      newSelected.add(keyId);
    } else {
      newSelected.delete(keyId);
    }
    setSelectedKeys(newSelected);
  };

  // 批量删除
  const handleBatchDelete = async () => {
    if (selectedKeys.size === 0) {
      alert('请先选择要删除的密钥');
      return;
    }
    if (!confirm(`确定要撤销选中的 ${selectedKeys.size} 个密钥吗？此操作不可逆！`)) {
      return;
    }

    let successCount = 0;
    let failCount = 0;
    for (const keyId of selectedKeys) {
      try {
        await api.revokeAPIKey(keyId);
        successCount++;
      } catch {
        failCount++;
      }
    }

    alert(`批量删除完成：成功 ${successCount} 个，失败 ${failCount} 个`);
    setSelectedKeys(new Set());
    loadStats();
    loadKeys();
  };

  // 批量复制
  const handleBatchCopy = async () => {
    if (selectedKeys.size === 0) {
      alert('请先选择要复制的密钥');
      return;
    }

    const keyValues: string[] = [];
    for (const keyId of selectedKeys) {
      try {
        const data = await api.viewAPIKey(keyId);
        keyValues.push(data.key);
      } catch {
        console.error(`Failed to get key ${keyId}`);
      }
    }

    if (keyValues.length > 0) {
      const allKeys = keyValues.join('\n');
      const success = await copyToClipboard(allKeys);
      if (success) {
        alert(`已复制 ${keyValues.length} 个密钥到剪贴板`);
      } else {
        alert('请手动复制:\n' + allKeys);
      }
    } else {
      alert('未能获取任何密钥');
    }
  };

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <div className="header-content">
          <h1>
            <KeyIcon />
            API 密钥管理
          </h1>
          <div className="header-actions">
            <Link to="/chat" className="btn-secondary">在线对话</Link>
            <Link to="/accounts" className="btn-secondary">账号管理</Link>
            <button className="btn-secondary" onClick={() => setShowKeepAliveModal(true)}>保活</button>
            <button className="btn-secondary" onClick={() => setShowSettingsModal(true)}>账户设置</button>
            <button className="btn-secondary" onClick={handleLogout}>退出登录</button>
          </div>
        </div>
      </header>

      <main className="dashboard-main">
        {/* 统计卡片 */}
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon">
              <CheckCircleIcon />
            </div>
            <div className="stat-info">
              <div className="stat-label">活跃密钥</div>
              <div className="stat-value">{stats.active_keys}</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">
              <ChartIcon />
            </div>
            <div className="stat-info">
              <div className="stat-label">总调用次数</div>
              <div className="stat-value">{stats.total_usage.toLocaleString()}</div>
            </div>
          </div>
        </div>

        {/* 生成密钥表单 */}
        <div className="card">
          <h2>生成新密钥</h2>
          <form onSubmit={handleGenerateKeys} className="generate-form">
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="count">数量</label>
                <input
                  type="number"
                  id="count"
                  min={1}
                  max={100}
                  value={generateForm.count}
                  onChange={(e) => setGenerateForm({ ...generateForm, count: parseInt(e.target.value) || 1 })}
                  required
                />
              </div>
              <div className="form-group">
                <label htmlFor="expiresDays">有效期（天）</label>
                <input
                  type="number"
                  id="expiresDays"
                  min={1}
                  max={3650}
                  value={generateForm.expiresDays}
                  onChange={(e) => setGenerateForm({ ...generateForm, expiresDays: parseInt(e.target.value) || 30 })}
                  required
                />
              </div>
              <div className="form-group">
                <label htmlFor="namePrefix">名称前缀</label>
                <input
                  type="text"
                  id="namePrefix"
                  value={generateForm.namePrefix}
                  onChange={(e) => setGenerateForm({ ...generateForm, namePrefix: e.target.value })}
                  required
                />
              </div>
            </div>
            <button type="submit" className="btn-primary">生成密钥</button>
          </form>
        </div>

        {/* 密钥列表 */}
        <div className="card">
          <div className="card-header-with-actions">
            <h2>密钥列表</h2>
            <div>
              {selectedKeys.size > 0 && (
                <>
                  <button className="btn-secondary" style={{ marginRight: '8px' }} onClick={handleBatchCopy}>
                    批量复制选中项 ({selectedKeys.size})
                  </button>
                  <button className="btn-danger" onClick={handleBatchDelete}>
                    批量删除选中项 ({selectedKeys.size})
                  </button>
                </>
              )}
            </div>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 50 }}>
                    <input
                      type="checkbox"
                      checked={keys.length > 0 && selectedKeys.size === keys.length}
                      onChange={(e) => handleSelectAll(e.target.checked)}
                    />
                  </th>
                  <th>ID</th>
                  <th>创建时间</th>
                  <th>过期时间</th>
                  <th>状态</th>
                  <th>使用次数</th>
                  <th>最后使用</th>
                  <th style={{ width: 280 }}>操作</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={8} className="loading">加载中...</td>
                  </tr>
                ) : keys.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="loading">暂无密钥</td>
                  </tr>
                ) : (
                  keys.map((key, index) => {
                    const status = getKeyStatus(key);
                    return (
                      <tr key={key.id}>
                        <td>
                          <input
                            type="checkbox"
                            checked={selectedKeys.has(key.id)}
                            onChange={(e) => handleSelectKey(key.id, e.target.checked)}
                          />
                        </td>
                        <td>{index + 1}</td>
                        <td>{formatDate(key.created_at)}</td>
                        <td>{formatDate(key.expires_at)}</td>
                        <td><span className={`status-badge ${status.className}`}>{status.text}</span></td>
                        <td>{key.usage_count}</td>
                        <td>{formatDate(key.last_used_at)}</td>
                        <td>
                          <div className="action-buttons">
                            <button className="action-btn btn-info" onClick={() => handleViewKeyLogs(key.id, `API Key #${index + 1}`)} title="查看日志">
                              📊
                            </button>
                            <button className="action-btn btn-secondary" onClick={() => handleViewAndCopyKey(key.id)} title="查看复制">
                              👁
                            </button>
                            <button className="action-btn btn-danger" onClick={() => handleRevokeKey(key.id)} title="撤销">
                              🗑
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>

      {/* 生成密钥成功模态框 */}
      {showKeysModal && (
        <div className="modal active" onClick={(e) => e.target === e.currentTarget && setShowKeysModal(false)}>
          <div className="modal-content">
            <div className="modal-header">
              <h2>✨ 密钥生成成功</h2>
              <button className="modal-close" onClick={() => setShowKeysModal(false)}>&times;</button>
            </div>
            <div className="modal-body">
              <p className="info-message">
                ℹ️ 密钥已生成，您可以随时在密钥列表中点击"查看复制"按钮查看。
              </p>
              <div className="keys-list">
                {generatedKeys.map((key) => (
                  <div key={key.id} className="key-item" onClick={() => key.key && handleCopyKey(key.key)}>
                    <div className="key-name">{key.name}</div>
                    <div className="key-value">{key.key}</div>
                  </div>
                ))}
              </div>
              <button className="btn-primary" onClick={handleCopyAllKeys}>复制所有密钥</button>
            </div>
          </div>
        </div>
      )}

      {/* 调用详情模态框 */}
      {showLogsModal && (
        <div className="modal active" onClick={(e) => e.target === e.currentTarget && setShowLogsModal(false)}>
          <div className="modal-content modal-large">
            <div className="modal-header">
              <h2>📊 {currentKeyName} - 调用详情</h2>
              <button className="modal-close" onClick={() => setShowLogsModal(false)}>&times;</button>
            </div>
            <div className="modal-body">
              {keyStats && (
                <>
                  <div className="stats-grid-small">
                    <div className="stat-card-small">
                      <div className="stat-label">总调用</div>
                      <div className="stat-value-small">{keyStats.total_calls}</div>
                    </div>
                    <div className="stat-card-small">
                      <div className="stat-label">成功率</div>
                      <div className="stat-value-small">{keyStats.success_rate}%</div>
                    </div>
                    <div className="stat-card-small">
                      <div className="stat-label">平均响应</div>
                      <div className="stat-value-small">{keyStats.avg_response_time}ms</div>
                    </div>
                    <div className="stat-card-small">
                      <div className="stat-label">错误次数</div>
                      <div className="stat-value-small">{keyStats.error_calls}</div>
                    </div>
                  </div>

                  <div className="section-title">按模型统计</div>
                  <div className="model-stats-container">
                    {keyStats.model_stats.length > 0 ? (
                      keyStats.model_stats.map((m) => (
                        <div key={m.model} className="model-stat-item">
                          <span className="model-name">{m.model}</span>
                          <span className="model-count">{m.count} 次</span>
                          <div className="model-bar">
                            <div
                              className="model-bar-fill"
                              style={{ width: `${(m.count / keyStats.total_calls) * 100}%` }}
                            />
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="no-data">暂无数据</p>
                    )}
                  </div>

                  <div className="section-title">最近7天调用趋势</div>
                  <div className="chart-container">
                    {keyStats.daily_stats.length > 0 ? (
                      (() => {
                        const maxCount = Math.max(...keyStats.daily_stats.map(d => d.count));
                        return keyStats.daily_stats.map((stat) => (
                          <div key={stat.date} className="chart-bar-wrapper">
                            <div
                              className="chart-bar"
                              style={{ height: `${maxCount > 0 ? (stat.count / maxCount) * 100 : 0}%` }}
                            >
                              <span className="chart-value">{stat.count}</span>
                            </div>
                            <div className="chart-label">{formatShortDate(stat.date)}</div>
                          </div>
                        ));
                      })()
                    ) : (
                      <p className="no-data">暂无数据</p>
                    )}
                  </div>
                </>
              )}

              <div className="section-title">调用日志</div>
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>时间</th>
                      <th>模型</th>
                      <th>状态</th>
                      <th>响应时间</th>
                      <th>IP 地址</th>
                      <th>端点</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="loading">暂无调用记录</td>
                      </tr>
                    ) : (
                      logs.map((log) => (
                        <tr key={log.id}>
                          <td>{formatDate(log.timestamp)}</td>
                          <td><code>{log.model || '-'}</code></td>
                          <td>
                            <span className={`status-badge ${log.status === 'success' ? 'status-active' : 'status-inactive'}`}>
                              {log.status === 'success' ? '✓ 成功' : '✗ 失败'}
                            </span>
                          </td>
                          <td>{log.response_time ? `${log.response_time}ms` : '-'}</td>
                          <td>{log.ip_address || '-'}</td>
                          <td><code>{log.endpoint || '-'}</code></td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              {logsTotal > 1 && currentKeyId && (
                <div className="pagination">
                  <div className="pagination-buttons">
                    {logsPage > 1 && (
                      <button className="btn-page" onClick={() => loadKeyLogs(currentKeyId, logsPage - 1)}>
                        « 上一页
                      </button>
                    )}
                    {Array.from({ length: Math.min(5, logsTotal) }, (_, i) => {
                      const page = Math.max(1, logsPage - 2) + i;
                      if (page > logsTotal) return null;
                      return (
                        <button
                          key={page}
                          className={`btn-page ${page === logsPage ? 'active' : ''}`}
                          onClick={() => loadKeyLogs(currentKeyId, page)}
                        >
                          {page}
                        </button>
                      );
                    })}
                    {logsPage < logsTotal && (
                      <button className="btn-page" onClick={() => loadKeyLogs(currentKeyId, logsPage + 1)}>
                        下一页 »
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 账户设置模态框 */}
      {showSettingsModal && (
        <div className="modal active" onClick={(e) => e.target === e.currentTarget && setShowSettingsModal(false)}>
          <div className="modal-content" style={{ maxWidth: 800 }}>
            <div className="modal-header">
              <h2>👤 账户设置</h2>
              <button className="modal-close" onClick={() => setShowSettingsModal(false)}>&times;</button>
            </div>
            <div className="modal-body">
              <AccountSettings onClose={() => setShowSettingsModal(false)} />
            </div>
          </div>
        </div>
      )}

      {/* 保活策略模态框 */}
      {showKeepAliveModal && (
        <div className="modal active" onClick={(e) => e.target === e.currentTarget && setShowKeepAliveModal(false)}>
          <div className="modal-content" style={{ maxWidth: 1400, width: '95vw', height: '90vh', display: 'flex', flexDirection: 'column' }}>
            <div className="modal-header">
              <h2>🕐 保活策略</h2>
              <button className="modal-close" onClick={() => setShowKeepAliveModal(false)}>&times;</button>
            </div>
            <div className="modal-body" style={{ flex: 1, overflow: 'auto' }}>
              <KeepAliveContent />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// 账户设置组件
function AccountSettings({ onClose: _onClose }: { onClose: () => void }) {
  const [newUsername, setNewUsername] = useState('');
  const [usernamePassword, setUsernamePassword] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleChangeUsername = async (e: FormEvent) => {
    e.preventDefault();
    if (!newUsername || !usernamePassword) {
      alert('请填写所有字段');
      return;
    }

    setIsLoading(true);
    try {
      await api.changeUsername({ new_username: newUsername, password: usernamePassword });
      alert('用户名修改成功，请重新登录');
      api.logout();
    } catch (error) {
      alert('修改失败: ' + (error instanceof Error ? error.message : '未知错误'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleChangePassword = async (e: FormEvent) => {
    e.preventDefault();
    if (!currentPassword || !newPassword || !confirmPassword) {
      alert('请填写所有字段');
      return;
    }
    if (newPassword !== confirmPassword) {
      alert('两次输入的新密码不一致');
      return;
    }

    setIsLoading(true);
    try {
      await api.changePassword({ current_password: currentPassword, new_password: newPassword });
      alert('密码修改成功，请重新登录');
      api.logout();
    } catch (error) {
      alert('修改失败: ' + (error instanceof Error ? error.message : '未知错误'));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
      <div>
        <h3 style={{ marginBottom: '1rem' }}>修改用户名</h3>
        <form onSubmit={handleChangeUsername}>
          <div className="form-group">
            <label>新用户名</label>
            <input
              type="text"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label>当前密码</label>
            <input
              type="password"
              value={usernamePassword}
              onChange={(e) => setUsernamePassword(e.target.value)}
              required
            />
          </div>
          <button type="submit" className="btn-primary" disabled={isLoading}>
            {isLoading ? '修改中...' : '修改用户名'}
          </button>
        </form>
      </div>

      <div>
        <h3 style={{ marginBottom: '1rem' }}>修改密码</h3>
        <form onSubmit={handleChangePassword}>
          <div className="form-group">
            <label>当前密码</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label>新密码</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label>确认新密码</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>
          <button type="submit" className="btn-primary" disabled={isLoading}>
            {isLoading ? '修改中...' : '修改密码'}
          </button>
        </form>
      </div>
    </div>
  );
}

// 保活内容组件
function KeepAliveContent() {
  const [task, setTask] = useState<import('../api/types').KeepAliveTask | null>(null);
  const [status, setStatus] = useState<import('../api/types').KeepAliveStatus | null>(null);
  const [logs, setLogs] = useState<import('../api/types').KeepAliveLog[]>([]);
  const [selectedLog, setSelectedLog] = useState<import('../api/types').KeepAliveLog | null>(null);
  const [accountLogs, setAccountLogs] = useState<import('../api/types').KeepAliveAccountLog[]>([]);
  const [selectedLogs, setSelectedLogs] = useState<Set<number>>(new Set());
  const [isLoading, setIsLoading] = useState(true);

  const [enabled, setEnabled] = useState(false);
  const [executeTime, setExecuteTime] = useState('03:00');

  const loadTask = useCallback(async () => {
    try {
      const data = await api.getKeepAliveTask();
      setTask(data);
      setEnabled(data.is_enabled ?? data.enabled ?? false);
      setExecuteTime(data.schedule_time || data.execute_time || '03:00');
    } catch (error) {
      console.error('Failed to load task:', error);
    }
  }, []);

  const loadStatus = useCallback(async () => {
    try {
      const data = await api.getKeepAliveStatus();
      setStatus(data);
    } catch (error) {
      console.error('Failed to load status:', error);
    }
  }, []);

  const loadLogs = useCallback(async () => {
    try {
      const data = await api.getKeepAliveLogs();
      setLogs(data);
    } catch (error) {
      console.error('Failed to load logs:', error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const loadAccountLogs = useCallback(async (logId: number) => {
    try {
      const data = await api.getKeepAliveAccountLogs(logId);
      setAccountLogs(data);
    } catch (error) {
      console.error('Failed to load account logs:', error);
    }
  }, []);

  useEffect(() => {
    loadTask();
    loadStatus();
    loadLogs();

    const interval = setInterval(() => {
      loadStatus();
    }, 5000);

    return () => clearInterval(interval);
  }, [loadTask, loadStatus, loadLogs]);

  const handleSelectLog = (log: import('../api/types').KeepAliveLog) => {
    setSelectedLog(log);
    loadAccountLogs(log.id);
  };

  const handleSaveTask = async () => {
    try {
      // 先获取当前任务配置，保留其他字段
      const currentTask = await api.getKeepAliveTask();
      await api.updateKeepAliveTask({
        is_enabled: enabled,
        schedule_time: executeTime,
        api_keepalive_enabled: currentTask.api_keepalive_enabled ?? true,
        api_keepalive_interval: currentTask.api_keepalive_interval || 30,
        auto_check_enabled: currentTask.auto_check_enabled ?? false,
        auto_check_interval: currentTask.auto_check_interval || 60,
        auto_check_auto_fix: currentTask.auto_check_auto_fix ?? true,
      });
      alert('配置已保存');
      loadTask();
    } catch (error) {
      alert('保存失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleExecute = async () => {
    try {
      await api.executeKeepAlive();
      alert('保活任务已开始执行');
      loadStatus();
      loadLogs();
    } catch (error) {
      alert('执行失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleCancel = async () => {
    try {
      await api.cancelKeepAlive();
      alert('保活任务已取消');
      loadStatus();
    } catch (error) {
      alert('取消失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleDeleteLog = async (logId: number) => {
    if (!confirm('确定要删除这条日志吗？')) return;
    try {
      await api.deleteKeepAliveLog(logId);
      loadLogs();
      if (selectedLog?.id === logId) {
        setSelectedLog(null);
        setAccountLogs([]);
      }
    } catch (error) {
      alert('删除失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleBatchDeleteLogs = async () => {
    if (selectedLogs.size === 0) { alert('请先选择要删除的日志'); return; }
    if (!confirm(`确定要删除选中的 ${selectedLogs.size} 条日志吗？`)) return;
    try {
      await api.bulkDeleteKeepAliveLogs(Array.from(selectedLogs));
      setSelectedLogs(new Set());
      loadLogs();
      if (selectedLog && selectedLogs.has(selectedLog.id)) {
        setSelectedLog(null);
        setAccountLogs([]);
      }
    } catch (error) {
      alert('批量删除失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleSelectLogCheckbox = (logId: number, checked: boolean) => {
    const newSelected = new Set(selectedLogs);
    checked ? newSelected.add(logId) : newSelected.delete(logId);
    setSelectedLogs(newSelected);
  };

  const getStatusText = (s: string) => {
    switch (s) {
      case 'running': return '运行中';
      case 'completed': return '已完成';
      case 'failed': return '失败';
      case 'cancelled': return '已取消';
      default: return s;
    }
  };

  const getStatusClass = (s: string) => {
    switch (s) {
      case 'running': return 'status-running';
      case 'completed': return 'status-active';
      case 'failed': return 'status-inactive';
      case 'cancelled': return 'status-expired';
      default: return '';
    }
  };

  return (
    <>
      <div className="keepalive-container">
        <div className="keepalive-section">
          <h3 style={{ marginBottom: '0.75rem' }}>任务配置</h3>

          {status && (
            <div className="info-message" style={{ marginBottom: '0.75rem', padding: '0.5rem 0.75rem', fontSize: '0.85rem' }}>
              {status.is_running ? (
                <>🔄 执行中 | 账号: {status.current_account || '-'} | 进度: {status.progress}/{status.total}</>
              ) : '⏸️ 任务未在运行'}
            </div>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem' }}>
              <span>启用定时保活</span>
              <label className="switch">
                <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
                <span className="slider"></span>
              </label>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem' }}>
              <span>执行时间</span>
              <input type="time" value={executeTime} onChange={(e) => setExecuteTime(e.target.value)} style={{ padding: '0.25rem 0.5rem' }} />
            </label>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button className="btn-primary" style={{ padding: '0.4rem 0.75rem', fontSize: '0.85rem' }} onClick={handleSaveTask}>保存配置</button>
              {status?.is_running ? (
                <button className="btn-danger" style={{ padding: '0.4rem 0.75rem', fontSize: '0.85rem' }} onClick={handleCancel}>中断任务</button>
              ) : (
                <button className="btn-secondary" style={{ padding: '0.4rem 0.75rem', fontSize: '0.85rem' }} onClick={handleExecute}>立即执行</button>
              )}
            </div>
          </div>

          {task && <p className="subtitle" style={{ fontSize: '0.8rem', marginBottom: '0.75rem' }}>上次执行: {(task.last_run_at || task.last_executed_at) ? formatDate(task.last_run_at || task.last_executed_at || '') : '从未执行'}</p>}

          <h3 style={{ marginTop: '0.5rem', marginBottom: '0.5rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-color)' }}>执行历史</h3>

          {selectedLogs.size > 0 && (
            <button className="btn-danger" style={{ marginBottom: '0.5rem', padding: '0.25rem 0.5rem', fontSize: '0.8rem' }} onClick={handleBatchDeleteLogs}>批量删除 ({selectedLogs.size})</button>
          )}

          {isLoading ? (
            <p className="loading">加载中...</p>
          ) : logs.length === 0 ? (
            <p className="no-data">暂无执行记录</p>
          ) : (
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {logs.map((log) => (
                <div key={log.id} className={`log-entry ${selectedLog?.id === log.id ? 'selected' : ''}`} onClick={() => handleSelectLog(log)}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <input type="checkbox" checked={selectedLogs.has(log.id)} onChange={(e) => { e.stopPropagation(); handleSelectLogCheckbox(log.id, e.target.checked); }} onClick={(e) => e.stopPropagation()} />
                    <div style={{ flex: 1 }}>
                      <div className="log-time">{formatDate(log.started_at)}</div>
                      <div className="log-status">
                        <span className={`status-badge ${getStatusClass(log.status)}`}>{getStatusText(log.status)}</span>
                        <span>成功: {log.success_count} / 失败: {log.failed_count}</span>
                      </div>
                    </div>
                    <button className="btn-danger" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }} onClick={(e) => { e.stopPropagation(); handleDeleteLog(log.id); }}>删除</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="keepalive-section">
          <h3>账号日志</h3>

          {!selectedLog ? (
            <p className="no-data">请从左侧选择一条执行记录</p>
          ) : accountLogs.length === 0 ? (
            <p className="no-data">暂无账号日志</p>
          ) : (
            <div style={{ maxHeight: 500, overflowY: 'auto' }}>
              {accountLogs.map((log) => (
                <div key={log.id} className="account-log">
                  <div className="account-log-header">
                    <span className="account-email">{log.account_name}</span>
                    <span className={`status-badge ${log.status === 'success' ? 'status-active' : 'status-inactive'}`}>{log.status === 'success' ? '成功' : '失败'}</span>
                  </div>
                  {log.message && (
                    <div className="account-log-message">
                      {log.message.split('\n').map((line, i) => (
                        <div key={i} className="log-line">{line}</div>
                      ))}
                    </div>
                  )}
                  <div className="log-time">{formatDate(log.created_at)}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <style>{`
        .keepalive-container { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; height: 100%; }
        @media (max-width: 1024px) { .keepalive-container { grid-template-columns: 1fr; } }
        .keepalive-section { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 1.5rem; overflow: hidden; display: flex; flex-direction: column; }
        .keepalive-section h3 { font-size: 1rem; font-weight: 600; margin-bottom: 0.75rem; color: var(--text-primary); flex-shrink: 0; }
        .switch { position: relative; display: inline-block; width: 48px; height: 24px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--border-color); transition: 0.4s; border-radius: 24px; }
        .slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: 0.4s; border-radius: 50%; }
        input:checked + .slider { background: var(--primary-gradient); }
        input:checked + .slider:before { transform: translateX(24px); }
        .log-entry { padding: 1rem; background: rgba(15, 23, 42, 0.4); border: 1px solid var(--border-color); border-radius: var(--radius-md); margin-bottom: 0.75rem; cursor: pointer; transition: all 0.2s; }
        .log-entry:hover { border-color: var(--primary-color); background: rgba(99, 102, 241, 0.05); }
        .log-entry.selected { border-color: var(--primary-color); background: rgba(99, 102, 241, 0.1); }
        .log-time { font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 0.25rem; }
        .log-status { display: flex; gap: 1rem; font-size: 0.875rem; align-items: center; }
        .account-log { padding: 0.75rem 1rem; background: rgba(15, 23, 42, 0.4); border: 1px solid var(--border-color); border-radius: var(--radius-md); margin-bottom: 0.75rem; }
        .account-log-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border-color); }
        .account-email { font-weight: 600; color: var(--text-primary); font-size: 0.9rem; }
        .account-log-message { font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.5rem; max-height: 300px; overflow-y: auto; }
        .log-line { padding: 0.2rem 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-family: 'Consolas', 'Monaco', monospace; line-height: 1.5; }
        .log-line:last-child { border-bottom: none; }
      `}</style>
    </>
  );
}
