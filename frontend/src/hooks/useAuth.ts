import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { TokenManager } from '../api/client';

// 路由守卫 Hook
export function useRequireAuth() {
  const navigate = useNavigate();
  const isAuthenticated = TokenManager.isAuthenticated();

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, navigate]);

  return isAuthenticated;
}
