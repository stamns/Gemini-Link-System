import { useState, useEffect, useRef, FormEvent, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import katex from 'katex';
import 'katex/dist/katex.min.css';
import type { ChatMessage, Model } from '../api/types';

// 配置 marked
marked.setOptions({
  breaks: true,
  gfm: true,
});

// 渲染数学公式
function renderMath(text: string): string {
  // 处理块级公式 $$...$$
  text = text.replace(/\$\$([\s\S]+?)\$\$/g, (_, formula) => {
    try {
      return katex.renderToString(formula.trim(), { displayMode: true, throwOnError: false });
    } catch {
      return `$$${formula}$$`;
    }
  });

  // 处理行内公式 $...$
  text = text.replace(/\$([^$\n]+?)\$/g, (_, formula) => {
    try {
      return katex.renderToString(formula.trim(), { displayMode: false, throwOnError: false });
    } catch {
      return `$${formula}$`;
    }
  });

  // 处理 \[...\] 块级公式
  text = text.replace(/\\\[([\s\S]+?)\\\]/g, (_, formula) => {
    try {
      return katex.renderToString(formula.trim(), { displayMode: true, throwOnError: false });
    } catch {
      return `\\[${formula}\\]`;
    }
  });

  // 处理 \(...\) 行内公式
  text = text.replace(/\\\(([\s\S]+?)\\\)/g, (_, formula) => {
    try {
      return katex.renderToString(formula.trim(), { displayMode: false, throwOnError: false });
    } catch {
      return `\\(${formula}\\)`;
    }
  });

  return text;
}

// 渲染 Markdown
function renderMarkdown(text: string): string {
  // 先处理数学公式
  text = renderMath(text);
  // 再渲染 Markdown
  const html = marked.parse(text) as string;
  // 清理 HTML
  return DOMPurify.sanitize(html, {
    ADD_TAGS: ['span'],
    ADD_ATTR: ['class', 'style'],
  });
}

interface MessageItem {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  isStreaming?: boolean;
  images?: string[];
}

export default function Chat() {
  const [messages, setMessages] = useState<MessageItem[]>([]);
  const [input, setInput] = useState('');
  const [model, setModel] = useState('gemini-auto');
  const [models, setModels] = useState<Model[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [uploadedImages, setUploadedImages] = useState<string[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // 加载模型列表
  useEffect(() => {
    const loadModels = async () => {
      try {
        const data = await api.getModels();
        setModels(data.data);
      } catch (error) {
        console.error('Failed to load models:', error);
      }
    };
    loadModels();
  }, []);

  // 滚动到底部
  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  // 处理文件上传
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files) return;

    for (const file of Array.from(files)) {
      if (file.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = (event) => {
          const base64 = event.target?.result as string;
          setUploadedImages((prev) => [...prev, base64]);
        };
        reader.readAsDataURL(file);
      }
    }

    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // 移除上传的图片
  const removeUploadedImage = (index: number) => {
    setUploadedImages((prev) => prev.filter((_, i) => i !== index));
  };

  // 发送消息
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if ((!input.trim() && uploadedImages.length === 0) || isLoading) return;

    const userContent = input.trim();
    const userImages = [...uploadedImages];

    const userMessage: MessageItem = {
      id: Date.now().toString(),
      role: 'user',
      content: userContent,
      images: userImages,
    };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setUploadedImages([]);
    setIsLoading(true);

    const assistantMessage: MessageItem = {
      id: (Date.now() + 1).toString(),
      role: 'assistant',
      content: '',
      isStreaming: true,
    };
    setMessages((prev) => [...prev, assistantMessage]);

    const apiMessages: ChatMessage[] = messages.map((m) => {
      if (m.images && m.images.length > 0) {
        return {
          role: m.role,
          content: [
            { type: 'text' as const, text: m.content },
            ...m.images.map((img) => ({
              type: 'image_url' as const,
              image_url: { url: img },
            })),
          ],
        };
      }
      return { role: m.role, content: m.content };
    });

    if (userImages.length > 0) {
      apiMessages.push({
        role: 'user',
        content: [
          { type: 'text', text: userContent },
          ...userImages.map((img) => ({
            type: 'image_url' as const,
            image_url: { url: img },
          })),
        ],
      });
    } else {
      apiMessages.push({ role: 'user', content: userContent });
    }

    try {
      let fullContent = '';
      for await (const chunk of api.streamChat({ model, messages: apiMessages })) {
        fullContent += chunk;
        setMessages((prev) =>
          prev.map((m) =>
            m.id === assistantMessage.id ? { ...m, content: fullContent } : m
          )
        );
      }

      setMessages((prev) =>
        prev.map((m) =>
          m.id === assistantMessage.id ? { ...m, isStreaming: false } : m
        )
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : '请求失败';
      setMessages((prev) =>
        prev.map((m) =>
          m.id === assistantMessage.id
            ? { ...m, content: `错误: ${errorMessage}`, isStreaming: false }
            : m
        )
      );
    } finally {
      setIsLoading(false);
    }
  };

  // 停止生成
  const handleStop = () => {
    setIsLoading(false);
    setMessages((prev) =>
      prev.map((m) => (m.isStreaming ? { ...m, isStreaming: false } : m))
    );
  };

  // 清空对话
  const handleClear = () => {
    if (messages.length > 0 && confirm('确定要清空对话吗？')) {
      setMessages([]);
    }
  };

  return (
    <div className="chat-container">
      <header className="chat-header">
        <h1>💬 在线对话</h1>
        <div className="header-actions">
          <select
            className="model-selector"
            value={model}
            onChange={(e) => setModel(e.target.value)}
          >
            {models.length > 0 ? (
              models.map((m) => (
                <option key={m.id} value={m.id}>{m.id}</option>
              ))
            ) : (
              <>
                <option value="gemini-auto">gemini-auto</option>
                <option value="gemini-2.5-flash">gemini-2.5-flash</option>
                <option value="gemini-2.5-pro">gemini-2.5-pro</option>
              </>
            )}
          </select>
          <button className="btn-secondary" onClick={handleClear}>清空对话</button>
          <Link to="/dashboard" className="btn-secondary">返回管理</Link>
        </div>
      </header>

      <div className="chat-messages">
        {messages.length === 0 && (
          <div className="no-data" style={{ marginTop: '2rem' }}>
            <h2 style={{ marginBottom: '0.5rem' }}>👋 欢迎使用在线对话</h2>
            <p>开始与 Gemini 对话吧！支持文字和图片输入。</p>
          </div>
        )}

        {messages.map((message) => (
          <div key={message.id} className={`message ${message.role}`}>
            <div className="message-avatar">
              {message.role === 'user' ? '👤' : '🤖'}
            </div>
            <div className="message-content">
              {message.images && message.images.length > 0 && (
                <div style={{ marginBottom: '0.5rem' }}>
                  {message.images.map((img, i) => (
                    <img key={i} src={img} alt="uploaded" style={{ maxWidth: 200, borderRadius: 8, marginRight: 8 }} />
                  ))}
                </div>
              )}
              {message.role === 'assistant' ? (
                <div dangerouslySetInnerHTML={{ __html: renderMarkdown(message.content || (message.isStreaming ? '正在思考...' : '')) }} />
              ) : (
                <div style={{ whiteSpace: 'pre-wrap' }}>{message.content}</div>
              )}
              {message.isStreaming && <span style={{ animation: 'blink 1s infinite' }}>▊</span>}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      <div className="chat-input-container">
        {uploadedImages.length > 0 && (
          <div style={{ marginBottom: '0.5rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            {uploadedImages.map((img, i) => (
              <div key={i} style={{ position: 'relative' }}>
                <img src={img} alt="preview" style={{ width: 60, height: 60, objectFit: 'cover', borderRadius: 8 }} />
                <button
                  onClick={() => removeUploadedImage(i)}
                  style={{ position: 'absolute', top: -8, right: -8, width: 20, height: 20, borderRadius: '50%', border: 'none', background: 'var(--danger-color)', color: 'white', cursor: 'pointer', fontSize: 12 }}
                >×</button>
              </div>
            ))}
          </div>
        )}

        <form onSubmit={handleSubmit} className="chat-input-wrapper">
          <input type="file" ref={fileInputRef} accept="image/*" multiple onChange={handleFileUpload} style={{ display: 'none' }} />
          <button type="button" className="btn-secondary" onClick={() => fileInputRef.current?.click()} style={{ padding: '0.75rem' }}>📎</button>
          <textarea
            className="chat-input"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSubmit(e);
              }
            }}
            placeholder="输入消息... (Shift+Enter 换行)"
            rows={1}
          />
          {isLoading ? (
            <button type="button" className="btn-danger" onClick={handleStop}>停止</button>
          ) : (
            <button type="submit" className="btn-primary" disabled={!input.trim() && uploadedImages.length === 0}>发送</button>
          )}
        </form>
      </div>

      <style>{`
        .chat-container { display: flex; flex-direction: column; height: 100vh; background: var(--bg-body); }
        .chat-header { background: var(--bg-card); border-bottom: 1px solid var(--border-color); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .chat-header h1 { margin: 0; font-size: 1.25rem; }
        .model-selector { padding: 0.5rem 1rem; background: var(--bg-input); border: 1px solid var(--border-color); border-radius: var(--radius-md); color: var(--text-primary); }
        .chat-messages { flex: 1; overflow-y: auto; padding: 2rem; display: flex; flex-direction: column; gap: 1.5rem; }
        .message { display: flex; gap: 1rem; max-width: 85%; animation: fadeIn 0.3s ease-in; }
        .message.user { align-self: flex-end; flex-direction: row-reverse; }
        .message.assistant { align-self: flex-start; }
        .message-avatar { width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; background: var(--bg-card); border: 1px solid var(--border-color); }
        .message.user .message-avatar { background: var(--primary-gradient); border: none; }
        .message-content { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 1rem 1.25rem; line-height: 1.6; word-wrap: break-word; max-width: 800px; }
        .message.user .message-content { background: var(--primary-color); color: white; border-color: var(--primary-color); }
        .chat-input-container { background: var(--bg-card); border-top: 1px solid var(--border-color); padding: 1rem 2rem; }
        .chat-input-wrapper { max-width: 900px; margin: 0 auto; display: flex; gap: 0.5rem; align-items: flex-end; }
        .chat-input { flex: 1; background: var(--bg-input); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 0.75rem 1rem; color: var(--text-primary); font-size: 0.95rem; resize: none; min-height: 48px; max-height: 200px; font-family: inherit; }
        .chat-input:focus { outline: none; border-color: var(--primary-color); }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes blink { 0%, 50% { opacity: 1; } 51%, 100% { opacity: 0; } }
      `}</style>
    </div>
  );
}
