import type {
  LoginRequest,
  LoginResponse,
  ChangePasswordRequest,
  ChangeUsernameRequest,
  Stats,
  APIKey,
  GenerateKeysRequest,
  KeyStats,
  LogsResponse,
  Account,
  AddAccountRequest,
  BulkAddAccountsRequest,
  UpdateAccountRequest,
  AccountCheckResult,
  KeepAliveTask,
  KeepAliveStatus,
  KeepAliveLog,
  KeepAliveAccountLog,
  ChatRequest,
  ModelsResponse,
} from './types';

// API 基础配置
const API_BASE = import.meta.env.VITE_API_BASE || '';

// Token 管理
export const TokenManager = {
  getToken(): string | null {
    return localStorage.getItem('token');
  },

  setToken(token: string): void {
    localStorage.setItem('token', token);
  },

  removeToken(): void {
    localStorage.removeItem('token');
  },

  isAuthenticated(): boolean {
    return !!this.getToken();
  },
};

// API 请求封装
class APIClient {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    url: string,
    options: RequestInit = {}
  ): Promise<T> {
    const token = TokenManager.getToken();
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options.headers,
    };

    const response = await fetch(this.baseUrl + url, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      TokenManager.removeToken();
      window.location.href = '/login';
      throw new Error('Authentication failed');
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Request failed' }));
      throw new Error(error.detail || `HTTP ${response.status}`);
    }

    // 处理空响应
    const text = await response.text();
    if (!text) {
      return {} as T;
    }

    return JSON.parse(text);
  }

  // ==================== 认证 API ====================

  async login(data: LoginRequest): Promise<LoginResponse> {
    const response = await fetch(this.baseUrl + '/admin/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Login failed' }));
      throw new Error(error.detail || 'Login failed');
    }

    const result = await response.json();
    TokenManager.setToken(result.access_token);
    return result;
  }

  async changePassword(data: ChangePasswordRequest): Promise<void> {
    await this.request('/admin/change-password', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async changeUsername(data: ChangeUsernameRequest): Promise<void> {
    await this.request('/admin/change-username', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  logout(): void {
    TokenManager.removeToken();
    window.location.href = '/login';
  }

  // ==================== 统计 API ====================

  async getStats(): Promise<Stats> {
    return this.request('/admin/stats');
  }

  // ==================== API 密钥 API ====================

  async getAPIKeys(): Promise<APIKey[]> {
    return this.request('/admin/api-keys');
  }

  async generateAPIKeys(data: GenerateKeysRequest): Promise<APIKey[]> {
    return this.request('/admin/api-keys', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async viewAPIKey(keyId: number): Promise<{ key: string }> {
    return this.request(`/admin/api-keys/${keyId}/view`);
  }

  async getKeyStats(keyId: number): Promise<KeyStats> {
    return this.request(`/admin/api-keys/${keyId}/stats`);
  }

  async getKeyLogs(keyId: number, page: number = 1, pageSize: number = 20): Promise<LogsResponse> {
    return this.request(`/admin/api-keys/${keyId}/logs?page=${page}&page_size=${pageSize}`);
  }

  async revokeAPIKey(keyId: number): Promise<void> {
    await this.request(`/admin/api-keys/${keyId}`, {
      method: 'DELETE',
    });
  }

  // ==================== 账号 API ====================

  async getAccounts(): Promise<Account[]> {
    return this.request('/admin/accounts');
  }

  async addAccount(data: AddAccountRequest): Promise<Account> {
    return this.request('/admin/accounts', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async bulkAddAccounts(data: BulkAddAccountsRequest): Promise<{ added: number; skipped: number }> {
    return this.request('/admin/accounts/bulk', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateAccount(index: number, data: UpdateAccountRequest): Promise<Account> {
    return this.request(`/admin/accounts/${index}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async deleteAccount(index: number): Promise<void> {
    await this.request(`/admin/accounts/${index}`, {
      method: 'DELETE',
    });
  }

  async bulkDeleteAccounts(indices: number[]): Promise<void> {
    await this.request('/admin/accounts/bulk-delete', {
      method: 'POST',
      body: JSON.stringify({ indices }),
    });
  }

  async testAccount(index: number): Promise<AccountCheckResult> {
    return this.request(`/admin/accounts/${index}/test`, {
      method: 'POST',
    });
  }

  async batchCheckAccounts(indices?: number[]): Promise<AccountCheckResult[]> {
    return this.request('/admin/accounts/batch-check', {
      method: 'POST',
      body: JSON.stringify({ indices }),
    });
  }

  async loginAccount(index: number): Promise<{ success: boolean; message: string }> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5 * 60 * 1000); // 5 minutes timeout

    try {
      const token = TokenManager.getToken();
      const response = await fetch(this.baseUrl + `/admin/accounts/${index}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token && { Authorization: `Bearer ${token}` }),
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Login failed' }));
        throw new Error(error.detail || 'Login failed');
      }

      return response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('登录超时，请检查浏览器状态');
      }
      throw error;
    }
  }

  // ==================== 保活任务 API ====================

  async getKeepAliveTask(): Promise<KeepAliveTask> {
    return this.request('/admin/keep-alive/task');
  }

  async updateKeepAliveTask(data: Partial<KeepAliveTask>): Promise<KeepAliveTask> {
    return this.request('/admin/keep-alive/task', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async executeKeepAlive(): Promise<{ message: string }> {
    return this.request('/admin/keep-alive/execute', {
      method: 'POST',
    });
  }

  async cancelKeepAlive(): Promise<{ message: string }> {
    return this.request('/admin/keep-alive/cancel', {
      method: 'POST',
    });
  }

  async getKeepAliveStatus(): Promise<KeepAliveStatus> {
    return this.request('/admin/keep-alive/status');
  }

  async getKeepAliveLogs(): Promise<KeepAliveLog[]> {
    return this.request('/admin/keep-alive/logs');
  }

  async getKeepAliveAccountLogs(logId: number): Promise<KeepAliveAccountLog[]> {
    return this.request(`/admin/keep-alive/logs/${logId}/accounts`);
  }

  async deleteKeepAliveLog(logId: number): Promise<void> {
    await this.request(`/admin/keep-alive/logs/${logId}`, {
      method: 'DELETE',
    });
  }

  async bulkDeleteKeepAliveLogs(logIds: number[]): Promise<void> {
    await this.request('/admin/keep-alive/logs/bulk-delete', {
      method: 'POST',
      body: JSON.stringify({ log_ids: logIds }),
    });
  }

  async executeAutoCheck(): Promise<{ message: string }> {
    return this.request('/admin/auto-check/execute', {
      method: 'POST',
    });
  }

  // ==================== 聊天 API ====================

  async getModels(): Promise<ModelsResponse> {
    return this.request('/admin/models');
  }

  async *streamChat(data: ChatRequest): AsyncGenerator<string, void, unknown> {
    const token = TokenManager.getToken();
    const response = await fetch(this.baseUrl + '/admin/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
      },
      body: JSON.stringify({ ...data, stream: true }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Chat failed' }));
      throw new Error(error.detail || 'Chat failed');
    }

    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error('No response body');
    }

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6);
          if (data === '[DONE]') {
            return;
          }
          try {
            const parsed = JSON.parse(data);
            const content = parsed.choices?.[0]?.delta?.content;
            if (content) {
              yield content;
            }
          } catch {
            // Ignore parse errors
          }
        }
      }
    }
  }
}

// 导出单例实例
export const api = new APIClient();

// 工具函数
export function formatDate(dateString: string | null): string {
  if (!dateString) return '-';
  const date = new Date(dateString);
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatShortDate(dateString: string): string {
  const date = new Date(dateString);
  return `${date.getMonth() + 1}/${date.getDate()}`;
}

export function getKeyStatus(key: APIKey): { text: string; className: string } {
  if (!key.is_active) {
    return { text: '已撤销', className: 'status-inactive' };
  }
  const now = new Date();
  const expiresAt = new Date(key.expires_at);
  if (expiresAt < now) {
    return { text: '已过期', className: 'status-expired' };
  }
  return { text: '活跃', className: 'status-active' };
}

export function getCookieStatusInfo(status: string): { text: string; className: string } {
  switch (status) {
    case 'valid':
      return { text: '有效', className: 'status-active' };
    case 'expired':
      return { text: '过期', className: 'status-inactive' };
    case 'banned':
      return { text: '被禁止', className: 'status-inactive' };
    case 'rate_limited':
      return { text: '限流', className: 'status-warning' };
    case 'checking':
      return { text: '检查中', className: 'status-checking' };
    default:
      return { text: '未知', className: 'status-expired' };
  }
}

export async function copyToClipboard(text: string): Promise<boolean> {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  }

  // Fallback
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();

  try {
    const successful = document.execCommand('copy');
    document.body.removeChild(textarea);
    return successful;
  } catch {
    document.body.removeChild(textarea);
    return false;
  }
}

// WebSocket 连接管理
export class WebSocketManager {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectInterval: number = 5000;
  private onMessage: ((data: string) => void) | null = null;

  constructor() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    this.url = `${protocol}//${window.location.host}/ws/admin/events`;
  }

  connect(onMessage: (data: string) => void): void {
    this.onMessage = onMessage;
    this.createConnection();
  }

  private createConnection(): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    this.ws = new WebSocket(this.url);

    this.ws.onmessage = (event) => {
      this.onMessage?.(event.data);
    };

    this.ws.onclose = () => {
      setTimeout(() => this.createConnection(), this.reconnectInterval);
    };

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      this.ws?.close();
    };
  }

  disconnect(): void {
    this.ws?.close();
    this.ws = null;
    this.onMessage = null;
  }
}

export const wsManager = new WebSocketManager();
