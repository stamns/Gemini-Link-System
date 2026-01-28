import { useState, useEffect, useCallback, FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { api, formatDate, getCookieStatusInfo, copyToClipboard } from '../api/client';
import type { Account, AddAccountRequest } from '../api/types';

export default function Accounts() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [selectedAccounts, setSelectedAccounts] = useState<Set<number>>(new Set());
  const [isLoading, setIsLoading] = useState(true);

  const [showAddModal, setShowAddModal] = useState(false);
  const [showBulkAddModal, setShowBulkAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showAutoCheckModal, setShowAutoCheckModal] = useState(false);
  const [editingAccount, setEditingAccount] = useState<Account | null>(null);

  const [addForm, setAddForm] = useState<AddAccountRequest>({
    name: '', secure_c_ses: '', csesidx: '', config_id: '', host_c_oses: '',
  });
  const [bulkConfigs, setBulkConfigs] = useState('');
  const [loginLoadingIndex, setLoginLoadingIndex] = useState<number | null>(null);

  // 自动检查配置
  const [autoCheckEnabled, setAutoCheckEnabled] = useState(false);
  const [autoCheckInterval, setAutoCheckInterval] = useState(60);
  const [autoCheckAutoFix, setAutoCheckAutoFix] = useState(true);

  const loadAccounts = useCallback(async () => {
    try {
      const data = await api.getAccounts();
      setAccounts(data);
    } catch (error) {
      console.error('Failed to load accounts:', error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAccounts();
    const interval = setInterval(loadAccounts, 10000);
    return () => clearInterval(interval);
  }, [loadAccounts]);

  const handleLogout = () => api.logout();

  const handleSelectAll = (checked: boolean) => {
    setSelectedAccounts(checked ? new Set(accounts.map((a) => a.index)) : new Set());
  };

  const handleSelectAccount = (index: number, checked: boolean) => {
    const newSelected = new Set(selectedAccounts);
    checked ? newSelected.add(index) : newSelected.delete(index);
    setSelectedAccounts(newSelected);
  };

  const handleAddAccount = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.addAccount(addForm);
      alert('账号添加成功');
      setShowAddModal(false);
      setAddForm({ name: '', secure_c_ses: '', csesidx: '', config_id: '', host_c_oses: '' });
      loadAccounts();
    } catch (error) {
      alert('添加失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleBulkAddAccounts = async (e: FormEvent) => {
    e.preventDefault();
    if (!bulkConfigs.trim()) { alert('请输入配置内容'); return; }
    try {
      const result = await api.bulkAddAccounts({ configs: bulkConfigs });
      alert(`批量添加完成：成功 ${result.added} 个，跳过 ${result.skipped} 个`);
      setShowBulkAddModal(false);
      setBulkConfigs('');
      loadAccounts();
    } catch (error) {
      alert('批量添加失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleEditAccount = async (e: FormEvent) => {
    e.preventDefault();
    if (!editingAccount) return;
    try {
      await api.updateAccount(editingAccount.index, {
        name: editingAccount.name, secure_c_ses: editingAccount.secure_c_ses,
        csesidx: editingAccount.csesidx, config_id: editingAccount.config_id, host_c_oses: editingAccount.host_c_oses,
      });
      alert('账号更新成功');
      setShowEditModal(false);
      setEditingAccount(null);
      loadAccounts();
    } catch (error) {
      alert('更新失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleDeleteAccount = async (index: number) => {
    if (!confirm('确定要删除这个账号吗？')) return;
    try {
      await api.deleteAccount(index);
      alert('账号已删除');
      loadAccounts();
    } catch (error) {
      alert('删除失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleBatchDelete = async () => {
    if (selectedAccounts.size === 0) { alert('请先选择要删除的账号'); return; }
    if (!confirm(`确定要删除选中的 ${selectedAccounts.size} 个账号吗？`)) return;
    try {
      await api.bulkDeleteAccounts(Array.from(selectedAccounts));
      alert('批量删除成功');
      setSelectedAccounts(new Set());
      loadAccounts();
    } catch (error) {
      alert('批量删除失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleCheckAccount = async (index: number) => {
    try {
      const result = await api.testAccount(index);
      alert(`检查结果: ${result.status}${result.message ? ` - ${result.message}` : ''}`);
      loadAccounts();
    } catch (error) {
      alert('检查失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const openAutoCheckModal = async () => {
    try {
      const task = await api.getKeepAliveTask();
      setAutoCheckEnabled(task.auto_check_enabled || false);
      setAutoCheckInterval(task.auto_check_interval || 60);
      setAutoCheckAutoFix(task.auto_check_auto_fix !== false);
      setShowAutoCheckModal(true);
    } catch (error) {
      alert('加载配置失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleSaveAutoCheck = async () => {
    try {
      // 先获取当前配置
      const currentTask = await api.getKeepAliveTask();
      // 合并更新 - 后端需要 is_enabled 和 schedule_time
      await api.updateKeepAliveTask({
        is_enabled: currentTask.is_enabled ?? true,
        schedule_time: currentTask.schedule_time || '03:00',
        api_keepalive_enabled: currentTask.api_keepalive_enabled ?? true,
        api_keepalive_interval: currentTask.api_keepalive_interval || 30,
        auto_check_enabled: autoCheckEnabled,
        auto_check_interval: autoCheckInterval,
        auto_check_auto_fix: autoCheckAutoFix,
      });
      alert('配置已保存');
      setShowAutoCheckModal(false);
    } catch (error) {
      alert('保存失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleExecuteAutoCheck = async () => {
    try {
      const result = await api.executeAutoCheck();
      alert(result.message || '自动检查已开始执行');
      loadAccounts();
    } catch (error) {
      alert('执行失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleBatchCheck = async () => {
    const indices = selectedAccounts.size > 0 ? Array.from(selectedAccounts) : undefined;
    alert('批量检查开始，请稍候...');
    try {
      await api.batchCheckAccounts(indices);
      loadAccounts();
      alert('批量检查完成');
    } catch (error) {
      alert('批量检查失败: ' + (error instanceof Error ? error.message : '未知错误'));
    }
  };

  const handleCopyAccount = async (account: Account) => {
    const config = `Name=${account.name}\nSECURE_C_SES=${account.secure_c_ses}\nCSESIDX=${account.csesidx}\nCONFIG_ID=${account.config_id}\nHOST_C_OSES=${account.host_c_oses}`;
    const success = await copyToClipboard(config);
    alert(success ? '配置已复制到剪贴板' : '复制失败');
  };

  const handleLoginAccount = async (index: number) => {
    setLoginLoadingIndex(index);
    try {
      const result = await api.loginAccount(index);
      alert(result.success ? '登录成功！' : '登录失败: ' + result.message);
      loadAccounts();
    } catch (error) {
      alert('登录失败: ' + (error instanceof Error ? error.message : '未知错误'));
    } finally {
      setLoginLoadingIndex(null);
    }
  };

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <div className="header-content">
          <h1>👥 账号管理</h1>
          <div className="header-actions">
            <Link to="/dashboard" className="btn-secondary">返回密钥管理</Link>
            <button className="btn-secondary" onClick={handleLogout}>退出登录</button>
          </div>
        </div>
      </header>

      <main className="dashboard-main">
        <div className="warning-message">⚠️ 重要提示：修改账号配置后会自动重新加载，无需重启服务。</div>

        <div className="card">
          <div className="card-header-with-actions">
            <h2>账号列表</h2>
            <div className="header-actions">
              <button className="btn-secondary" onClick={openAutoCheckModal}>自动检查</button>
              <button className="btn-secondary" onClick={handleBatchCheck}>批量检查</button>
              <button className="btn-danger" onClick={handleBatchDelete} disabled={selectedAccounts.size === 0}>
                批量删除{selectedAccounts.size > 0 ? ` (${selectedAccounts.size})` : ''}
              </button>
              <button className="btn-secondary" onClick={() => setShowBulkAddModal(true)}>批量添加</button>
              <button className="btn-primary" onClick={() => setShowAddModal(true)}>添加账号</button>
            </div>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 50 }}>
                    <input type="checkbox" checked={accounts.length > 0 && selectedAccounts.size === accounts.length} onChange={(e) => handleSelectAll(e.target.checked)} />
                  </th>
                  <th>索引</th><th>名称</th><th>Cookie 状态</th><th>最后检查</th><th>操作</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={6} className="loading">加载中...</td></tr>
                ) : accounts.length === 0 ? (
                  <tr><td colSpan={6} className="loading">暂无账号</td></tr>
                ) : (
                  accounts.map((account) => {
                    const status = getCookieStatusInfo(account.cookie_status);
                    return (
                      <tr key={account.index}>
                        <td><input type="checkbox" checked={selectedAccounts.has(account.index)} onChange={(e) => handleSelectAccount(account.index, e.target.checked)} /></td>
                        <td>{account.index}</td>
                        <td>{account.name}</td>
                        <td><span className={`status-badge ${status.className}`}>{status.text}</span></td>
                        <td>{formatDate(account.last_check_time)}</td>
                        <td>
                          <div className="action-buttons">
                            <button className="btn-secondary" onClick={() => handleCopyAccount(account)}>复制</button>
                            <button className="btn-secondary" onClick={() => handleCheckAccount(account.index)}>检查</button>
                            <button className="btn-secondary" onClick={() => handleLoginAccount(account.index)} disabled={loginLoadingIndex === account.index}>
                              {loginLoadingIndex === account.index ? '登录中...' : '登录'}
                            </button>
                            <button className="btn-secondary" onClick={() => { setEditingAccount(account); setShowEditModal(true); }}>编辑</button>
                            <button className="btn-danger" onClick={() => handleDeleteAccount(account.index)}>删除</button>
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

      {/* 添加账号模态框 */}
      {showAddModal && (
        <div className="modal active" onClick={(e) => e.target === e.currentTarget && setShowAddModal(false)}>
          <div className="modal-content">
            <div className="modal-header">
              <h2>添加账号</h2>
              <button className="modal-close" onClick={() => setShowAddModal(false)}>&times;</button>
            </div>
            <div className="modal-body">
              <form onSubmit={handleAddAccount}>
                <div className="form-group"><label>名称</label><input type="text" value={addForm.name} onChange={(e) => setAddForm({ ...addForm, name: e.target.value })} required /></div>
                <div className="form-group"><label>SECURE_C_SES</label><input type="text" value={addForm.secure_c_ses} onChange={(e) => setAddForm({ ...addForm, secure_c_ses: e.target.value })} required /></div>
                <div className="form-group"><label>CSESIDX</label><input type="text" value={addForm.csesidx} onChange={(e) => setAddForm({ ...addForm, csesidx: e.target.value })} required /></div>
                <div className="form-group"><label>CONFIG_ID</label><input type="text" value={addForm.config_id} onChange={(e) => setAddForm({ ...addForm, config_id: e.target.value })} required /></div>
                <div className="form-group"><label>HOST_C_OSES</label><input type="text" value={addForm.host_c_oses} onChange={(e) => setAddForm({ ...addForm, host_c_oses: e.target.value })} required /></div>
                <div className="modal-footer"><button type="button" className="btn-secondary" onClick={() => setShowAddModal(false)}>取消</button><button type="submit" className="btn-primary">添加</button></div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* 批量添加模态框 */}
      {showBulkAddModal && (
        <div className="modal active" onClick={(e) => e.target === e.currentTarget && setShowBulkAddModal(false)}>
          <div className="modal-content modal-large">
            <div className="modal-header">
              <h2>批量添加账号</h2>
              <button className="modal-close" onClick={() => setShowBulkAddModal(false)}>&times;</button>
            </div>
            <div className="modal-body">
              <form onSubmit={handleBulkAddAccounts}>
                <div className="form-group">
                  <textarea value={bulkConfigs} onChange={(e) => setBulkConfigs(e.target.value)} rows={15} placeholder="粘贴配置内容..." style={{ width: '100%', fontFamily: 'monospace' }} />
                </div>
                <div className="modal-footer"><button type="button" className="btn-secondary" onClick={() => setShowBulkAddModal(false)}>取消</button><button type="submit" className="btn-primary">批量添加</button></div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* 编辑账号模态框 */}
      {showEditModal && editingAccount && (
        <div className="modal active" onClick={(e) => e.target === e.currentTarget && setShowEditModal(false)}>
          <div className="modal-content">
            <div className="modal-header">
              <h2>编辑账号</h2>
              <button className="modal-close" onClick={() => setShowEditModal(false)}>&times;</button>
            </div>
            <div className="modal-body">
              <form onSubmit={handleEditAccount}>
                <div className="form-group"><label>名称</label><input type="text" value={editingAccount.name} onChange={(e) => setEditingAccount({ ...editingAccount, name: e.target.value })} required /></div>
                <div className="form-group"><label>SECURE_C_SES</label><input type="text" value={editingAccount.secure_c_ses} onChange={(e) => setEditingAccount({ ...editingAccount, secure_c_ses: e.target.value })} required /></div>
                <div className="form-group"><label>CSESIDX</label><input type="text" value={editingAccount.csesidx} onChange={(e) => setEditingAccount({ ...editingAccount, csesidx: e.target.value })} required /></div>
                <div className="form-group"><label>CONFIG_ID</label><input type="text" value={editingAccount.config_id} onChange={(e) => setEditingAccount({ ...editingAccount, config_id: e.target.value })} required /></div>
                <div className="form-group"><label>HOST_C_OSES</label><input type="text" value={editingAccount.host_c_oses} onChange={(e) => setEditingAccount({ ...editingAccount, host_c_oses: e.target.value })} required /></div>
                <div className="modal-footer"><button type="button" className="btn-secondary" onClick={() => setShowEditModal(false)}>取消</button><button type="submit" className="btn-primary">保存</button></div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* 自动检查配置模态框 */}
      {showAutoCheckModal && (
        <div className="modal active" onClick={(e) => e.target === e.currentTarget && setShowAutoCheckModal(false)}>
          <div className="modal-content" style={{ maxWidth: 500 }}>
            <div className="modal-header">
              <h2>🔍 自动检查配置</h2>
              <button className="modal-close" onClick={() => setShowAutoCheckModal(false)}>&times;</button>
            </div>
            <div className="modal-body">
              <div className="form-group" style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
                  <span style={{ fontWeight: 500 }}>启用自动检查</span>
                  <input type="checkbox" checked={autoCheckEnabled} onChange={(e) => setAutoCheckEnabled(e.target.checked)} style={{ width: 18, height: 18 }} />
                </label>
              </div>

              <div className="form-group" style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 500 }}>检查间隔</label>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <input type="number" min={5} max={1440} value={autoCheckInterval} onChange={(e) => setAutoCheckInterval(parseInt(e.target.value) || 60)} style={{ flex: 1 }} />
                  <span style={{ color: 'var(--text-secondary)' }}>分钟</span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>建议设置为 30-120 分钟</p>
              </div>

              <div className="form-group" style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', padding: '0.75rem', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)', cursor: 'pointer' }}>
                  <input type="checkbox" checked={autoCheckAutoFix} onChange={(e) => setAutoCheckAutoFix(e.target.checked)} style={{ width: 18, height: 18, marginTop: 2 }} />
                  <div>
                    <div style={{ fontWeight: 500, marginBottom: '0.25rem' }}>检测到无效 Cookie 时自动修复</div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>启用后，发现无效账号会自动调用浏览器保活来更新 Cookie</div>
                  </div>
                </label>
              </div>

              <div style={{ padding: '0.75rem', background: 'rgba(59, 130, 246, 0.1)', border: '1px solid rgba(59, 130, 246, 0.2)', borderRadius: 'var(--radius-md)', marginBottom: '1.5rem' }}>
                <div style={{ fontWeight: 500, marginBottom: '0.5rem', color: 'var(--info-color)' }}>💡 功能说明</div>
                <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  <li>系统会按设定间隔自动检查所有账号的 Cookie 状态</li>
                  <li>检测到无效 Cookie 时，会自动调用浏览器保活来更新</li>
                  <li>只有失效的账号会被更新，有效的账号不会处理</li>
                </ul>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color)' }}>
                <button type="button" className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowAutoCheckModal(false)}>取消</button>
                <button type="button" className="btn-secondary" style={{ flex: 1 }} onClick={handleExecuteAutoCheck}>立即执行</button>
                <button type="button" className="btn-primary" style={{ flex: 1 }} onClick={handleSaveAutoCheck}>保存配置</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
