import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line
} from 'recharts';
import { 
  ChartBarIcon, 
  PieChartIcon, 
  TrendingUpIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';
import { api } from '../../services/api';

interface ComparisonByType {
  [key: string]: {
    open_source_count: number;
    premium_count: number;
    overlap_count: number;
    open_source_coverage: number;
    premium_coverage: number;
  };
}

interface SourceComparison {
  [key: string]: {
    total_indicators: number;
    unique_indicators: number;
    types: string[];
    avg_confidence: number;
    latest_update: string;
  };
}

interface TrendData {
  daily_data: Array<{
    date: string;
    open_source: number;
    premium: number;
  }>;
}

interface DetailedComparisonData {
  overview: any;
  by_type: ComparisonByType;
  by_source: {
    open_source: SourceComparison;
    premium: SourceComparison;
  };
  trends: TrendData;
}

interface DetailedFeedComparisonProps {
  days?: number;
  className?: string;
}

export const DetailedFeedComparison: React.FC<DetailedFeedComparisonProps> = ({ 
  days = 30, 
  className = '' 
}) => {
  const [selectedDays, setSelectedDays] = useState(days);
  const [activeTab, setActiveTab] = useState<'overview' | 'by-type' | 'by-source' | 'trends'>('overview');

  const { data, isLoading, error } = useQuery({
    queryKey: ['feed-comparison-detailed', selectedDays],
    queryFn: () => api.get(`/feed-comparison/comprehensive?days=${selectedDays}`),
    refetchInterval: 300000, // Refresh every 5 minutes
  });

  const comparisonData = data?.data as DetailedComparisonData;

  const COLORS = ['#3B82F6', '#8B5CF6', '#EF4444', '#10B981', '#F59E0B'];

  const renderOverviewTab = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-blue-50 rounded-lg p-4">
          <div className="text-2xl font-bold text-blue-600">
            {comparisonData?.overview?.open_source_coverage || 0}%
          </div>
          <div className="text-sm text-blue-800">Open Source Coverage</div>
        </div>
        
        <div className="bg-purple-50 rounded-lg p-4">
          <div className="text-2xl font-bold text-purple-600">
            {comparisonData?.overview?.premium_coverage || 0}%
          </div>
          <div className="text-sm text-purple-800">Premium Coverage</div>
        </div>
        
        <div className="bg-green-50 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-600">
            {comparisonData?.overview?.overlap_percentage || 0}%
          </div>
          <div className="text-sm text-green-800">Overall Overlap</div>
        </div>
        
        <div className="bg-orange-50 rounded-lg p-4">
          <div className="text-2xl font-bold text-orange-600">
            {comparisonData?.overview?.shared_indicators || 0}
          </div>
          <div className="text-sm text-orange-800">Shared Indicators</div>
        </div>
      </div>

      {/* Pie Chart for Distribution */}
      <div className="bg-white rounded-lg p-4">
        <h4 className="text-lg font-semibold mb-4">Indicator Distribution</h4>
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={[
                { name: 'Unique Open Source', value: comparisonData?.overview?.unique_open_source || 0 },
                { name: 'Unique Premium', value: comparisonData?.overview?.unique_premium || 0 },
                { name: 'Shared', value: comparisonData?.overview?.shared_indicators || 0 }
              ]}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              outerRadius={80}
              fill="#8884d8"
              dataKey="value"
            >
              {COLORS.map((color, index) => (
                <Cell key={`cell-${index}`} fill={color} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );

  const renderByTypeTab = () => {
    if (!comparisonData?.by_type) return <div>No data available</div>;

    const chartData = Object.entries(comparisonData.by_type).map(([type, data]) => ({
      type: type.toUpperCase(),
      openSource: data.open_source_count,
      premium: data.premium_count,
      overlap: data.overlap_count,
      openSourceCoverage: data.open_source_coverage,
      premiumCoverage: data.premium_coverage
    }));

    return (
      <div className="space-y-6">
        <div className="bg-white rounded-lg p-4">
          <h4 className="text-lg font-semibold mb-4">Comparison by Indicator Type</h4>
          <ResponsiveContainer width="100%" height={400}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="type" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="openSource" fill="#3B82F6" name="Open Source" />
              <Bar dataKey="premium" fill="#8B5CF6" name="Premium" />
              <Bar dataKey="overlap" fill="#10B981" name="Overlap" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-white rounded-lg p-4">
            <h5 className="font-semibold mb-3">Coverage by Type</h5>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="type" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="openSourceCoverage" fill="#3B82F6" name="Open Source %" />
                <Bar dataKey="premiumCoverage" fill="#8B5CF6" name="Premium %" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    );
  };

  const renderBySourceTab = () => {
    if (!comparisonData?.by_source) return <div>No data available</div>;

    const openSourceData = Object.entries(comparisonData.by_source.open_source || {}).map(([source, data]) => ({
      source,
      indicators: data.total_indicators,
      unique: data.unique_indicators,
      confidence: data.avg_confidence
    }));

    const premiumData = Object.entries(comparisonData.by_source.premium || {}).map(([source, data]) => ({
      source,
      indicators: data.total_indicators,
      unique: data.unique_indicators,
      confidence: data.avg_confidence
    }));

    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white rounded-lg p-4">
            <h4 className="text-lg font-semibold mb-4">Open Source Sources</h4>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={openSourceData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="source" angle={-45} textAnchor="end" height={80} />
                <YAxis />
                <Tooltip />
                <Bar dataKey="indicators" fill="#3B82F6" name="Total Indicators" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="bg-white rounded-lg p-4">
            <h4 className="text-lg font-semibold mb-4">Premium Sources</h4>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={premiumData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="source" angle={-45} textAnchor="end" height={80} />
                <YAxis />
                <Tooltip />
                <Bar dataKey="indicators" fill="#8B5CF6" name="Total Indicators" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white rounded-lg p-4">
          <h4 className="text-lg font-semibold mb-4">Source Confidence Comparison</h4>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={[...openSourceData, ...premiumData]}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="source" angle={-45} textAnchor="end" height={80} />
              <YAxis />
              <Tooltip />
              <Bar dataKey="confidence" fill="#10B981" name="Avg Confidence" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    );
  };

  const renderTrendsTab = () => {
    if (!comparisonData?.trends?.daily_data) return <div>No data available</div>;

    return (
      <div className="space-y-6">
        <div className="bg-white rounded-lg p-4">
          <h4 className="text-lg font-semibold mb-4">Daily Trend Comparison</h4>
          <ResponsiveContainer width="100%" height={400}>
            <LineChart data={comparisonData.trends.daily_data}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="open_source" stroke="#3B82F6" name="Open Source" />
              <Line type="monotone" dataKey="premium" stroke="#8B5CF6" name="Premium" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-blue-50 rounded-lg p-4">
            <h5 className="font-semibold text-blue-900">Open Source Trend</h5>
            <div className="text-2xl font-bold text-blue-600">
              {comparisonData.trends.daily_data.reduce((sum, day) => sum + day.open_source, 0)}
            </div>
            <div className="text-sm text-blue-700">Total indicators in period</div>
          </div>

          <div className="bg-purple-50 rounded-lg p-4">
            <h5 className="font-semibold text-purple-900">Premium Trend</h5>
            <div className="text-2xl font-bold text-purple-600">
              {comparisonData.trends.daily_data.reduce((sum, day) => sum + day.premium, 0)}
            </div>
            <div className="text-sm text-purple-700">Total indicators in period</div>
          </div>
        </div>
      </div>
    );
  };

  if (isLoading) {
    return (
      <div className={`bg-white rounded-lg shadow-md p-6 ${className}`}>
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/3 mb-4"></div>
          <div className="h-8 bg-gray-200 rounded w-1/2 mb-4"></div>
          <div className="h-64 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`bg-white rounded-lg shadow-md p-6 ${className}`}>
        <div className="text-center text-red-500">
          Failed to load detailed comparison data
        </div>
      </div>
    );
  }

  return (
    <div className={`bg-white rounded-lg shadow-md p-6 ${className}`}>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <ChartBarIcon className="h-6 w-6 text-blue-600 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900">
            Detailed Feed Comparison
          </h3>
        </div>
        <select
          value={selectedDays}
          onChange={(e) => setSelectedDays(Number(e.target.value))}
          className="text-sm border border-gray-300 rounded px-2 py-1"
        >
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
          <option value={180}>Last 6 months</option>
          <option value={365}>Last year</option>
        </select>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 mb-6">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'overview', label: 'Overview', icon: PieChartIcon },
            { id: 'by-type', label: 'By Type', icon: DocumentTextIcon },
            { id: 'by-source', label: 'By Source', icon: ChartBarIcon },
            { id: 'trends', label: 'Trends', icon: TrendingUpIcon }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <tab.icon className="h-4 w-4 inline mr-1" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="min-h-[400px]">
        {activeTab === 'overview' && renderOverviewTab()}
        {activeTab === 'by-type' && renderByTypeTab()}
        {activeTab === 'by-source' && renderBySourceTab()}
        {activeTab === 'trends' && renderTrendsTab()}
      </div>
    </div>
  );
};
