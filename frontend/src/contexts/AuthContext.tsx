import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { api } from '../services/api';

interface User {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  is_verified: boolean;
  is_mfa_enabled: boolean;
  last_login?: string;
  created_at: string;
  updated_at: string;
  azure_ad_id?: string;
  azure_ad_email?: string;
  azure_ad_name?: string;
  roles: string[];
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

type AuthAction =
  | { type: 'LOGIN_START' }
  | { type: 'LOGIN_SUCCESS'; payload: User }
  | { type: 'LOGIN_FAILURE'; payload: string }
  | { type: 'LOGOUT' }
  | { type: 'CLEAR_ERROR' }
  | { type: 'SET_LOADING'; payload: boolean };

const initialState: AuthState = {
  user: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,
};

function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'LOGIN_START':
      return {
        ...state,
        isLoading: true,
        error: null,
      };
    case 'LOGIN_SUCCESS':
      return {
        ...state,
        user: action.payload,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      };
    case 'LOGIN_FAILURE':
      return {
        ...state,
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: action.payload,
      };
    case 'LOGOUT':
      return {
        ...state,
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
      };
    case 'CLEAR_ERROR':
      return {
        ...state,
        error: null,
      };
    case 'SET_LOADING':
      return {
        ...state,
        isLoading: action.payload,
      };
    default:
      return state;
  }
}

interface AuthContextType {
  state: AuthState;
  login: (username: string, password: string) => Promise<void>;
  loginWithAzureAD: (code: string, state: string) => Promise<void>;
  mfaLogin: (sessionToken: string, mfaCode: string, useBackupCode?: boolean) => Promise<void>;
  logout: () => Promise<void>;
  clearError: () => void;
  refreshAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(authReducer, initialState);

  const login = async (username: string, password: string) => {
    try {
      dispatch({ type: 'LOGIN_START' });

      const response = await api.post('/auth/login', {
        username,
        password,
        auth_method: 'internal',
      });

      const { access_token, refresh_token, user, requires_mfa } = response.data;

      // Store tokens
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('refresh_token', refresh_token);

      if (requires_mfa) {
        // Store session token for MFA
        localStorage.setItem('mfa_session_token', access_token);
        throw new Error('MFA_REQUIRED');
      }

      // Set auth header
      api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;

      dispatch({ type: 'LOGIN_SUCCESS', payload: user });
    } catch (error: any) {
      if (error.message === 'MFA_REQUIRED') {
        throw error;
      }
      
      const errorMessage = error.response?.data?.detail || 'Login failed';
      dispatch({ type: 'LOGIN_FAILURE', payload: errorMessage });
      throw new Error(errorMessage);
    }
  };

  const loginWithAzureAD = async (code: string, state: string) => {
    try {
      dispatch({ type: 'LOGIN_START' });

      const response = await api.post('/auth/azure-ad/login', {
        code,
        state,
      });

      const { access_token, refresh_token, user } = response.data;

      // Store tokens
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('refresh_token', refresh_token);

      // Set auth header
      api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;

      dispatch({ type: 'LOGIN_SUCCESS', payload: user });
    } catch (error: any) {
      const errorMessage = error.response?.data?.detail || 'Azure AD login failed';
      dispatch({ type: 'LOGIN_FAILURE', payload: errorMessage });
      throw new Error(errorMessage);
    }
  };

  const mfaLogin = async (sessionToken: string, mfaCode: string, useBackupCode = false) => {
    try {
      dispatch({ type: 'LOGIN_START' });

      const response = await api.post('/auth/mfa/login', {
        session_token: sessionToken,
        mfa_code: mfaCode,
        use_backup_code: useBackupCode,
      });

      const { access_token, refresh_token, user } = response.data;

      // Store tokens
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('refresh_token', refresh_token);

      // Clear MFA session token
      localStorage.removeItem('mfa_session_token');

      // Set auth header
      api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;

      dispatch({ type: 'LOGIN_SUCCESS', payload: user });
    } catch (error: any) {
      const errorMessage = error.response?.data?.detail || 'MFA login failed';
      dispatch({ type: 'LOGIN_FAILURE', payload: errorMessage });
      throw new Error(errorMessage);
    }
  };

  const logout = async () => {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        await api.post('/auth/logout', {
          refresh_token: refreshToken,
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear tokens and auth header
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('mfa_session_token');
      delete api.defaults.headers.common['Authorization'];

      dispatch({ type: 'LOGOUT' });
    }
  };

  const clearError = () => {
    dispatch({ type: 'CLEAR_ERROR' });
  };

  const refreshAuth = async () => {
    try {
      const accessToken = localStorage.getItem('access_token');
      if (!accessToken) {
        dispatch({ type: 'SET_LOADING', payload: false });
        return;
      }

      // Set auth header
      api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;

      // Get current user
      const response = await api.get('/auth/me');
      const user = response.data;

      dispatch({ type: 'LOGIN_SUCCESS', payload: user });
    } catch (error) {
      // Token is invalid, clear auth state
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('mfa_session_token');
      delete api.defaults.headers.common['Authorization'];

      dispatch({ type: 'LOGOUT' });
    }
  };

  // Check auth status on mount
  useEffect(() => {
    refreshAuth();
  }, []);

  const value: AuthContextType = {
    state,
    login,
    loginWithAzureAD,
    mfaLogin,
    logout,
    clearError,
    refreshAuth,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
