import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { 
  ChartBarIcon, 
  TrendingUpIcon, 
  DocumentTextIcon,
  ClockIcon,
  RefreshIcon
} from '@heroicons/react/24/outline';
import { api } from '../../services/api';

interface FeedComparisonData {
  open_source_coverage: number;
  premium_coverage: number;
  overlap_percentage: number;
  unique_open_source: number;
  unique_premium: number;
  shared_indicators: number;
  total_open_source: number;
  total_premium: number;
}

interface FeedComparisonCardProps {
  days?: number;
  className?: string;
}

export const FeedComparisonCard: React.FC<FeedComparisonCardProps> = ({ 
  days = 30, 
  className = '' 
}) => {
  const [selectedDays, setSelectedDays] = useState(days);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['feed-comparison', selectedDays],
    queryFn: () => api.get(`/feed-comparison/overview?days=${selectedDays}`),
    refetchInterval: 300000, // Refresh every 5 minutes
  });

  const comparisonData = data?.data as FeedComparisonData;

  const getCoverageColor = (percentage: number) => {
    if (percentage >= 80) return 'text-green-600';
    if (percentage >= 60) return 'text-yellow-600';
    if (percentage >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  const getCoverageBgColor = (percentage: number) => {
    if (percentage >= 80) return 'bg-green-100';
    if (percentage >= 60) return 'bg-yellow-100';
    if (percentage >= 40) return 'bg-orange-100';
    return 'bg-red-100';
  };

  if (isLoading) {
    return (
      <div className={`bg-white rounded-lg shadow-md p-6 ${className}`}>
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/3 mb-4"></div>
          <div className="h-8 bg-gray-200 rounded w-1/2 mb-4"></div>
          <div className="space-y-3">
            <div className="h-4 bg-gray-200 rounded"></div>
            <div className="h-4 bg-gray-200 rounded w-3/4"></div>
            <div className="h-4 bg-gray-200 rounded w-1/2"></div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`bg-white rounded-lg shadow-md p-6 ${className}`}>
        <div className="text-center">
          <div className="text-red-500 mb-2">Failed to load feed comparison data</div>
          <button
            onClick={() => refetch()}
            className="text-blue-600 hover:text-blue-800 text-sm"
          >
            Try again
          </button>
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
            Feed Comparison Analysis
          </h3>
        </div>
        <div className="flex items-center space-x-2">
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
          <button
            onClick={() => refetch()}
            className="text-gray-400 hover:text-gray-600"
          >
            <RefreshIcon className="h-4 w-4" />
          </button>
        </div>
      </div>

      {comparisonData && (
        <div className="space-y-6">
          {/* Main Coverage Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="text-center">
              <div className={`text-2xl font-bold ${getCoverageColor(comparisonData.open_source_coverage)}`}>
                {comparisonData.open_source_coverage}%
              </div>
              <div className="text-sm text-gray-600">Open Source Coverage</div>
              <div className="text-xs text-gray-500 mt-1">
                {comparisonData.total_open_source} indicators
              </div>
            </div>
            
            <div className="text-center">
              <div className={`text-2xl font-bold ${getCoverageColor(comparisonData.premium_coverage)}`}>
                {comparisonData.premium_coverage}%
              </div>
              <div className="text-sm text-gray-600">Premium Coverage</div>
              <div className="text-xs text-gray-500 mt-1">
                {comparisonData.total_premium} indicators
              </div>
            </div>
            
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">
                {comparisonData.overlap_percentage}%
              </div>
              <div className="text-sm text-gray-600">Overall Overlap</div>
              <div className="text-xs text-gray-500 mt-1">
                {comparisonData.shared_indicators} shared
              </div>
            </div>
          </div>

          {/* Coverage Bars */}
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Open Source Coverage</span>
                <span>{comparisonData.open_source_coverage}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className={`h-2 rounded-full ${getCoverageBgColor(comparisonData.open_source_coverage)}`}
                  style={{ width: `${Math.min(comparisonData.open_source_coverage, 100)}%` }}
                ></div>
              </div>
            </div>
            
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Premium Coverage</span>
                <span>{comparisonData.premium_coverage}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className={`h-2 rounded-full ${getCoverageBgColor(comparisonData.premium_coverage)}`}
                  style={{ width: `${Math.min(comparisonData.premium_coverage, 100)}%` }}
                ></div>
              </div>
            </div>
          </div>

          {/* Detailed Stats */}
          <div className="grid grid-cols-2 gap-4 pt-4 border-t border-gray-200">
            <div className="text-center">
              <div className="text-lg font-semibold text-green-600">
                {comparisonData.unique_open_source}
              </div>
              <div className="text-xs text-gray-600">Unique Open Source</div>
            </div>
            
            <div className="text-center">
              <div className="text-lg font-semibold text-purple-600">
                {comparisonData.unique_premium}
              </div>
              <div className="text-xs text-gray-600">Unique Premium</div>
            </div>
          </div>

          {/* Insights */}
          <div className="bg-blue-50 rounded-lg p-4">
            <h4 className="font-medium text-blue-900 mb-2">💡 Insights</h4>
            <div className="text-sm text-blue-800 space-y-1">
              {comparisonData.open_source_coverage >= 80 && (
                <div>• Open source feeds provide excellent coverage of premium indicators</div>
              )}
              {comparisonData.premium_coverage >= 80 && (
                <div>• Premium feeds capture most open source indicators</div>
              )}
              {comparisonData.overlap_percentage >= 70 && (
                <div>• High overlap suggests good correlation between feed types</div>
              )}
              {comparisonData.unique_open_source > comparisonData.unique_premium && (
                <div>• Open source feeds provide additional unique indicators</div>
              )}
              {comparisonData.unique_premium > comparisonData.unique_open_source && (
                <div>• Premium feeds provide additional unique indicators</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
