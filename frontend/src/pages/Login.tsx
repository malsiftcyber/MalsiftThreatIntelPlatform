import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../services/api';
import { toast } from 'react-hot-toast';
import Logo from '../components/Logo';

interface LoginFormData {
  username: string;
  password: string;
}

interface MFAFormData {
  mfaCode: string;
  useBackupCode: boolean;
}

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { state, login, mfaLogin, clearError } = useAuth();
  
  const [loginData, setLoginData] = useState<LoginFormData>({
    username: '',
    password: '',
  });
  
  const [mfaData, setMfaData] = useState<MFAFormData>({
    mfaCode: '',
    useBackupCode: false,
  });
  
  const [isLoading, setIsLoading] = useState(false);
  const [showMFA, setShowMFA] = useState(false);
  const [sessionToken, setSessionToken] = useState('');
  const [authMethod, setAuthMethod] = useState<'internal' | 'azure'>('internal');
  const [azureLoginUrl, setAzureLoginUrl] = useState('');

  // Redirect if already authenticated
  useEffect(() => {
    if (state.isAuthenticated) {
      const from = location.state?.from?.pathname || '/dashboard';
      navigate(from, { replace: true });
    }
  }, [state.isAuthenticated, navigate, location]);

  // Get Azure AD login URL
  useEffect(() => {
    const getAzureLoginUrl = async () => {
      try {
        const response = await api.get('/auth/azure-ad/login-url');
        setAzureLoginUrl(response.data.login_url);
      } catch (error) {
        console.error('Failed to get Azure AD login URL:', error);
      }
    };

    getAzureLoginUrl();
  }, []);

  const handleLoginChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setLoginData({
      ...loginData,
      [e.target.name]: e.target.value,
    });
  };

  const handleMFAChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setMfaData({
      ...mfaData,
      [e.target.name]: e.target.value,
    });
  };

  const handleInternalLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    clearError();

    try {
      await login(loginData.username, loginData.password);
      toast.success('Login successful!');
    } catch (error: any) {
      if (error.message === 'MFA_REQUIRED') {
        setShowMFA(true);
        setSessionToken(localStorage.getItem('mfa_session_token') || '');
      } else {
        toast.error(error.message || 'Login failed');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleMFALogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    clearError();

    try {
      await mfaLogin(sessionToken, mfaData.mfaCode, mfaData.useBackupCode);
      toast.success('MFA verification successful!');
    } catch (error: any) {
      toast.error(error.message || 'MFA verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleAzureADLogin = () => {
    if (azureLoginUrl) {
      window.location.href = azureLoginUrl;
    } else {
      toast.error('Azure AD is not configured');
    }
  };

  const handleBackToLogin = () => {
    setShowMFA(false);
    setMfaData({ mfaCode: '', useBackupCode: false });
    localStorage.removeItem('mfa_session_token');
  };

  if (state.isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="flex justify-center mb-4">
            <Logo variant="full" size="lg" />
          </div>
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (showMFA) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <div>
            <div className="flex justify-center mb-6">
              <Logo variant="full" size="xl" />
            </div>
            <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
              Multi-Factor Authentication
            </h2>
            <p className="mt-2 text-center text-sm text-gray-600">
              Enter the code from your authenticator app
            </p>
          </div>
          
          <form className="mt-8 space-y-6" onSubmit={handleMFALogin}>
            <div className="rounded-md shadow-sm -space-y-px">
              <div>
                <label htmlFor="mfaCode" className="sr-only">
                  MFA Code
                </label>
                <input
                  id="mfaCode"
                  name="mfaCode"
                  type="text"
                  required
                  className="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                  placeholder="Enter 6-digit code"
                  value={mfaData.mfaCode}
                  onChange={handleMFAChange}
                  maxLength={6}
                />
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input
                  id="useBackupCode"
                  name="useBackupCode"
                  type="checkbox"
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  checked={mfaData.useBackupCode}
                  onChange={(e) => setMfaData({ ...mfaData, useBackupCode: e.target.checked })}
                />
                <label htmlFor="useBackupCode" className="ml-2 block text-sm text-gray-900">
                  Use backup code
                </label>
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={isLoading}
                className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
              >
                {isLoading ? 'Verifying...' : 'Verify'}
              </button>
            </div>

            <div className="text-center">
              <button
                type="button"
                onClick={handleBackToLogin}
                className="text-sm text-blue-600 hover:text-blue-500"
              >
                Back to login
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
                      <div className="flex justify-center mb-6">
              <Logo variant="full" size="xl" />
            </div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Sign in to Malsift
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Cyber Threat Intelligence Platform
          </p>
        </div>
        
        <div className="mt-8 space-y-6">
          {/* Auth Method Tabs */}
          <div className="flex rounded-md shadow-sm">
            <button
              type="button"
              onClick={() => setAuthMethod('internal')}
              className={`flex-1 py-2 px-4 text-sm font-medium rounded-l-md border ${
                authMethod === 'internal'
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
              }`}
            >
              Internal Login
            </button>
            <button
              type="button"
              onClick={() => setAuthMethod('azure')}
              className={`flex-1 py-2 px-4 text-sm font-medium rounded-r-md border-t border-r border-b ${
                authMethod === 'azure'
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
              }`}
            >
              Azure AD
            </button>
          </div>

          {authMethod === 'internal' ? (
            <form className="mt-8 space-y-6" onSubmit={handleInternalLogin}>
              <div className="rounded-md shadow-sm -space-y-px">
                <div>
                  <label htmlFor="username" className="sr-only">
                    Username
                  </label>
                  <input
                    id="username"
                    name="username"
                    type="text"
                    required
                    className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                    placeholder="Username"
                    value={loginData.username}
                    onChange={handleLoginChange}
                  />
                </div>
                <div>
                  <label htmlFor="password" className="sr-only">
                    Password
                  </label>
                  <input
                    id="password"
                    name="password"
                    type="password"
                    required
                    className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                    placeholder="Password"
                    value={loginData.password}
                    onChange={handleLoginChange}
                  />
                </div>
              </div>

              {state.error && (
                <div className="rounded-md bg-red-50 p-4">
                  <div className="flex">
                    <div className="ml-3">
                      <h3 className="text-sm font-medium text-red-800">
                        {state.error}
                      </h3>
                    </div>
                  </div>
                </div>
              )}

              <div>
                <button
                  type="submit"
                  disabled={isLoading}
                  className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                >
                  {isLoading ? 'Signing in...' : 'Sign in'}
                </button>
              </div>
            </form>
          ) : (
            <div className="mt-8 space-y-6">
              <div className="text-center">
                <p className="text-sm text-gray-600 mb-4">
                  Sign in with your Azure Active Directory account
                </p>
                <button
                  type="button"
                  onClick={handleAzureADLogin}
                  disabled={!azureLoginUrl}
                  className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                >
                  Sign in with Azure AD
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="text-center">
          <p className="text-xs text-gray-500">
            Malsift - Cyber Threat Intelligence Platform
          </p>
        </div>
      </div>
    </div>
  );
}
