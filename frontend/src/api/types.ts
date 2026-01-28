// API 响应类型定义

// 认证相关
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface ChangeUsernameRequest {
  new_username: string;
  password: string;
}

// 统计相关
export interface Stats {
  active_keys: number;
  total_usage: number;
}

// API 密钥相关
export interface APIKey {
  id: number;
  name: string;
  key?: string;
  is_active: boolean;
  created_at: string;
  expires_at: string;
  usage_count: number;
  last_used_at: string | null;
}

export interface GenerateKeysRequest {
  count: number;
  expires_days: number;
  name_prefix: string;
}

export interface KeyStats {
  key_name: string;
  total_calls: number;
  success_rate: number;
  avg_response_time: number;
  error_calls: number;
  model_stats: ModelStat[];
  daily_stats: DailyStat[];
}

export interface ModelStat {
  model: string;
  count: number;
}

export interface DailyStat {
  date: string;
  count: number;
}

export interface CallLog {
  id: number;
  timestamp: string;
  model: string | null;
  status: 'success' | 'error';
  response_time: number | null;
  ip_address: string | null;
  endpoint: string | null;
}

export interface LogsResponse {
  logs: CallLog[];
  total: number;
  page: number;
  page_size: number;
}

// 账号相关
export interface Account {
  index: number;
  name: string;
  secure_c_ses: string;
  csesidx: string;
  config_id: string;
  host_c_oses: string;
  cookie_status: CookieStatus;
  last_check_time: string | null;
  cookie_expires_at: string | null;
}

export type CookieStatus = 'valid' | 'expired' | 'banned' | 'rate_limited' | 'unknown' | 'checking';

export interface AddAccountRequest {
  name: string;
  secure_c_ses: string;
  csesidx: string;
  config_id: string;
  host_c_oses: string;
}

export interface BulkAddAccountsRequest {
  configs: string;
}

export interface UpdateAccountRequest {
  name?: string;
  secure_c_ses?: string;
  csesidx?: string;
  config_id?: string;
  host_c_oses?: string;
}

export interface AccountCheckResult {
  index: number;
  name: string;
  status: CookieStatus;
  message?: string;
}

// 保活任务相关
export interface KeepAliveTask {
  id?: number;
  is_enabled?: boolean;
  enabled?: boolean;
  schedule_time?: string;
  execute_time?: string;
  api_keepalive_enabled?: boolean;
  api_keepalive_interval?: number;
  auto_check_enabled?: boolean;
  auto_check_interval?: number;
  auto_check_auto_fix?: boolean;
  last_run_at?: string | null;
  last_executed_at?: string | null;
  last_auto_check_at?: string | null;
}

export interface KeepAliveStatus {
  is_running: boolean;
  current_account: string | null;
  progress: number;
  total: number;
}

export interface KeepAliveLog {
  id: number;
  task_id: number;
  started_at: string;
  finished_at: string | null;
  status: string;
  total_count: number;
  success_count: number;
  failed_count: number;
  message: string | null;
}

export interface KeepAliveAccountLog {
  id: number;
  account_name: string;
  status: 'success' | 'failed';
  message: string | null;
  created_at: string;
}

// 聊天相关
export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string | ContentPart[];
}

export interface ContentPart {
  type: 'text' | 'image_url';
  text?: string;
  image_url?: {
    url: string;
  };
}

export interface ChatRequest {
  model: string;
  messages: ChatMessage[];
  stream?: boolean;
  temperature?: number;
  top_p?: number;
}

export interface ChatCompletionChunk {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: {
    index: number;
    delta: {
      role?: string;
      content?: string;
    };
    finish_reason: string | null;
  }[];
}

// 模型列表
export interface Model {
  id: string;
  object: string;
  created: number;
  owned_by: string;
}

export interface ModelsResponse {
  object: string;
  data: Model[];
}
