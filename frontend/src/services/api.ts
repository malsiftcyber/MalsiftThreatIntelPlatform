import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for adding auth tokens
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized access
      localStorage.removeItem('auth_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// API endpoints
export const endpoints = {
  // Indicators
  indicators: '/api/v1/indicators',
  indicatorsSummary: '/api/v1/indicators/summary/stats',
  indicatorsDeduplicate: '/api/v1/indicators/deduplicate',
  indicatorsSearch: (query: string) => `/api/v1/indicators/search/${query}`,
  indicatorsByType: (type: string) => `/api/v1/indicators/by-type/${type}`,
  indicatorsByLevel: (level: string) => `/api/v1/indicators/by-level/${level}`,
  indicatorsBySource: (sourceId: number) => `/api/v1/indicators/by-source/${sourceId}`,

  // Sources
  sources: '/api/v1/sources',

  // Feeds
  feeds: '/api/v1/feeds',
  feedsJobs: '/api/v1/feeds/jobs',
  feedsFetchAll: '/api/v1/feeds/fetch-all',
  feedsSources: '/api/v1/feeds/sources',

  // Campaigns
  campaigns: '/api/v1/campaigns',

  // Dark Web
  darkweb: '/api/v1/darkweb',
  darkwebStatus: '/api/v1/darkweb/status',
  darkwebScrapeAll: '/api/v1/darkweb/scrape-all',

  // Jobs
  jobs: '/api/v1/jobs',

  // Exclusions
  exclusions: '/api/v1/exclusions',
  exclusionsStats: '/api/v1/exclusions/stats/summary',
  exclusionsTest: '/api/v1/exclusions/test',
  exclusionsBulk: '/api/v1/exclusions/bulk',
  exclusionsImport: '/api/v1/exclusions/import',
  exclusionsToggle: (id: number) => `/api/v1/exclusions/${id}/toggle`,
  exclusionsCheck: (type: string, value: string) => `/api/v1/exclusions/check/${type}/${value}`,

  // Authentication
  auth: "/auth",
  authLogin: "/auth/login",
  authMfaLogin: "/auth/mfa/login",
  authMfaSetup: "/auth/mfa/setup",
  authMfaVerify: "/auth/mfa/verify",
  authMfaDisable: "/auth/mfa/disable",
  authRefresh: "/auth/refresh",
  authLogout: "/auth/logout",
  authMe: "/auth/me",
  authStatus: "/auth/status",
  authAzureAdLoginUrl: "/auth/azure-ad/login-url",
  authAzureAdLogin: "/auth/azure-ad/login",
  authUsers: "/auth/users",
  authUser: (id: number) => `/auth/users/${id}`,
  authChangePassword: "/auth/change-password",
  authResetPassword: "/auth/reset-password",
  authSessions: "/auth/sessions",
  authSession: (id: number) => `/auth/sessions/${id}`,

  // Health
  health: '/health',
};

export default api;
