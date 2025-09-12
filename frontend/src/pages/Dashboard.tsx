import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ChartBarIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CpuChipIcon,
  GlobeAltIcon,
  EyeIcon,
  ClockIcon,
  CurrencyDollarIcon
} from '@heroicons/react/24/outline';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { api } from '../services/api';
import { FeedComparisonDashboard } from '../components/feed-comparison/FeedComparisonDashboard';
import { EDRDashboard } from '../components/edr/EDRDashboard';

interface DashboardStats {
  total_indicators: number;
  total_sources: number;
  total_campaigns: number;
  active_feeds: number;
  last_24h_indicators: number;
  last_24h_campaigns: number;
  deduplication_rate: number;
  feed_comparison_stats: {
    total_open_source: number;
    total_premium: number;
    overlap_percentage: number;
    unique_open_source: number;
    unique_premium: number;
  };
  edr_stats: {
    total_connections: number;
    active_connections: number;
    total_extractions: number;
    total_indicators: number;
    unknown_indicators: number;
    analyzed_indicators: number;
    malicious_indicators: number;
    total_llm_cost: number;
  };
}

interface IndicatorTrend {
  date: string;
  indicators: number;
  campaigns: number;
}

interface SourceBreakdown {
  source: string;
  indicators: number;
  campaigns: number;
}

interface ThreatLevelBreakdown {
  level: string;
  count: number;
  color: string;
}

export const Dashboard: React.FC = () => {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => api.get('/dashboard/stats'),
    refetchInterval: 30000,
  });

  const { data: trends } = useQuery({
    queryKey: ['indicator-trends'],
    queryFn: () => api.get('/indicators/trends'),
  });

  const dashboardStats = stats?.data as DashboardStats || {} as DashboardStats;
  const indicatorTrends = trends?.data as IndicatorTrend[] || [];
  const sourceBreakdown: SourceBreakdown[] = [
    { source: 'CISA', indicators: 1250, campaigns: 45 },
    { source: 'AlienVault OTX', indicators: 2100, campaigns: 78 },
    { source: 'VirusTotal', indicators: 3200, campaigns: 120 },
    { source: 'Crowdstrike', indicators: 1800, campaigns: 65 },
    { source: 'Mandiant', indicators: 1500, campaigns: 55 },
  ];

  const threatLevelData: ThreatLevelBreakdown[] = [
    { level: 'Critical', count: 45, color: '#ef4444' },
    { level: 'High', count: 120, color: '#f97316' },
    { level: 'Medium', count: 350, color: '#eab308' },
    { level: 'Low', count: 180, color: '#22c55e' },
  ];

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/3 mb-6"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-24 bg-gray-200 rounded"></div>
            ))}
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="h-64 bg-gray-200 rounded"></div>
            <div className="h-64 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <div className="text-sm text-gray-500">
          Last updated: {new Date().toLocaleString()}
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow-md p-6">
          <div className="flex items-center">
            <ChartBarIcon className="h-8 w-8 text-blue-600" />
            <div className="ml-3">
              <div className="text-2xl font-bold text-blue-600">
                {dashboardStats.total_indicators?.toLocaleString() || '0'}
              </div>
              <div className="text-sm text-blue-800">Total Indicators</div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-md p-6">
          <div className="flex items-center">
            <GlobeAltIcon className="h-8 w-8 text-green-600" />
            <div className="ml-3">
              <div className="text-2xl font-bold text-green-600">
                {dashboardStats.total_sources || '0'}
              </div>
              <div className="text-sm text-green-800">Threat Sources</div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-md p-6">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-orange-600" />
            <div className="ml-3">
              <div className="text-2xl font-bold text-orange-600">
                {dashboardStats.total_campaigns || '0'}
              </div>
              <div className="text-sm text-orange-800">Active Campaigns</div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-md p-6">
          <div className="flex items-center">
            <ShieldCheckIcon className="h-8 w-8 text-purple-600" />
            <div className="ml-3">
              <div className="text-2xl font-bold text-purple-600">
                {dashboardStats.active_feeds || '0'}
              </div>
              <div className="text-sm text-purple-800">Active Feeds</div>
            </div>
          </div>
        </div>
      </div>

      {/* Feed Comparison Dashboard */}
      <FeedComparisonDashboard />

      {/* EDR Integration Dashboard */}
      <EDRDashboard />

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Indicator Trends */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Indicator Trends (Last 7 Days)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={indicatorTrends}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="indicators" stroke="#3b82f6" strokeWidth={2} />
              <Line type="monotone" dataKey="campaigns" stroke="#ef4444" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Source Breakdown */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Sources by Indicators</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={sourceBreakdown}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="source" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="indicators" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Threat Level Distribution */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Threat Level Distribution</h3>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={threatLevelData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ level, count }) => `${level}: ${count}`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="count"
              >
                {threatLevelData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          
          <div className="space-y-3">
            {threatLevelData.map((item) => (
              <div key={item.level} className="flex items-center">
                <div
                  className="w-4 h-4 rounded-full mr-3"
                  style={{ backgroundColor: item.color }}
                ></div>
                <span className="text-sm font-medium text-gray-700">{item.level}</span>
                <span className="ml-auto text-sm text-gray-500">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
        <div className="space-y-3">
          <div className="flex items-center text-sm text-gray-600">
            <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
            {dashboardStats.last_24h_indicators || 0} new indicators in last 24 hours
          </div>
          <div className="flex items-center text-sm text-gray-600">
            <div className="w-2 h-2 bg-blue-500 rounded-full mr-2"></div>
            {dashboardStats.last_24h_campaigns || 0} new campaigns detected
          </div>
          <div className="flex items-center text-sm text-gray-600">
            <div className="w-2 h-2 bg-purple-500 rounded-full mr-2"></div>
            {(dashboardStats.deduplication_rate * 100)?.toFixed(1) || '0'}% deduplication rate
          </div>
          {dashboardStats.edr_stats && (
            <>
              <div className="flex items-center text-sm text-gray-600">
                <div className="w-2 h-2 bg-orange-500 rounded-full mr-2"></div>
                {dashboardStats.edr_stats.unknown_indicators || 0} EDR indicators require LLM analysis
              </div>
              <div className="flex items-center text-sm text-gray-600">
                <div className="w-2 h-2 bg-red-500 rounded-full mr-2"></div>
                {dashboardStats.edr_stats.malicious_indicators || 0} indicators flagged as malicious
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
