import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ChartBarIcon,
  CogIcon,
  PlayIcon,
  StopIcon,
  EyeIcon,
  CpuChipIcon
} from '@heroicons/react/24/outline';
import { api } from '../../services/api';

interface EDRConnection {
  id: number;
  name: string;
  platform: 'crowdstrike' | 'sentinelone' | 'defender';
  is_active: boolean;
  last_sync: string | null;
  created_at: string;
}

interface EDRStats {
  total_connections: number;
  active_connections: number;
  total_extractions: number;
  total_indicators: number;
  unknown_indicators: number;
  analyzed_indicators: number;
  malicious_indicators: number;
  total_llm_cost: number;
  last_24h_indicators: number;
  last_24h_analyses: number;
}

interface EDRDashboardProps {
  className?: string;
}

export const EDRDashboard: React.FC<EDRDashboardProps> = ({ className = '' }) => {
  const [selectedConnection, setSelectedConnection] = useState<number | null>(null);
  const queryClient = useQueryClient();

  // Fetch EDR connections
  const { data: connections, isLoading: connectionsLoading } = useQuery({
    queryKey: ['edr-connections'],
    queryFn: () => api.get('/edr/connections'),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Fetch EDR dashboard stats
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['edr-dashboard-stats'],
    queryFn: () => api.get('/edr/dashboard/stats'),
    refetchInterval: 30000,
  });

  // Test connection mutation
  const testConnectionMutation = useMutation({
    mutationFn: (connectionId: number) => api.post(`/edr/connections/${connectionId}/test`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['edr-connections'] });
    },
  });

  const edrConnections = connections?.data as EDRConnection[] || [];
  const edrStats = stats?.data as EDRStats || {} as EDRStats;

  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case 'crowdstrike':
        return '🛡️';
      case 'sentinelone':
        return '🔍';
      case 'defender':
        return '🛡️';
      default:
        return '🔧';
    }
  };

  const getPlatformColor = (platform: string) => {
    switch (platform) {
      case 'crowdstrike':
        return 'text-blue-600 bg-blue-100';
      case 'sentinelone':
        return 'text-purple-600 bg-purple-100';
      case 'defender':
        return 'text-green-600 bg-green-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  if (connectionsLoading || statsLoading) {
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

  return (
    <div className={`bg-white rounded-lg shadow-md p-6 ${className}`}>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <ShieldCheckIcon className="h-6 w-6 text-blue-600 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900">
            EDR Integration Dashboard
          </h3>
        </div>
        <button className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">
          Add Connection
        </button>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="bg-blue-50 rounded-lg p-4">
          <div className="flex items-center">
            <CogIcon className="h-8 w-8 text-blue-600" />
            <div className="ml-3">
              <div className="text-2xl font-bold text-blue-600">
                {edrStats.total_connections || 0}
              </div>
              <div className="text-sm text-blue-800">Total Connections</div>
            </div>
          </div>
        </div>

        <div className="bg-green-50 rounded-lg p-4">
          <div className="flex items-center">
            <ChartBarIcon className="h-8 w-8 text-green-600" />
            <div className="ml-3">
              <div className="text-2xl font-bold text-green-600">
                {edrStats.total_indicators || 0}
              </div>
              <div className="text-sm text-green-800">Total Indicators</div>
            </div>
          </div>
        </div>

        <div className="bg-orange-50 rounded-lg p-4">
          <div className="flex items-center">
            <ExclamationTriangleIcon className="h-8 w-8 text-orange-600" />
            <div className="ml-3">
              <div className="text-2xl font-bold text-orange-600">
                {edrStats.unknown_indicators || 0}
              </div>
              <div className="text-sm text-orange-800">Unknown Indicators</div>
            </div>
          </div>
        </div>

        <div className="bg-purple-50 rounded-lg p-4">
          <div className="flex items-center">
            <CpuChipIcon className="h-8 w-8 text-purple-600" />
            <div className="ml-3">
              <div className="text-2xl font-bold text-purple-600">
                {edrStats.analyzed_indicators || 0}
              </div>
              <div className="text-sm text-purple-800">LLM Analyzed</div>
            </div>
          </div>
        </div>
      </div>

      {/* EDR Connections */}
      <div className="mb-6">
        <h4 className="text-md font-semibold text-gray-900 mb-3">EDR Connections</h4>
        <div className="space-y-3">
          {edrConnections.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <ShieldCheckIcon className="h-12 w-12 mx-auto mb-2 text-gray-300" />
              <p>No EDR connections configured</p>
              <p className="text-sm">Add your first EDR connection to start monitoring</p>
            </div>
          ) : (
            edrConnections.map((connection) => (
              <div
                key={connection.id}
                className={`border rounded-lg p-4 hover:bg-gray-50 cursor-pointer ${
                  selectedConnection === connection.id ? 'border-blue-500 bg-blue-50' : 'border-gray-200'
                }`}
                onClick={() => setSelectedConnection(connection.id)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <span className="text-2xl mr-3">
                      {getPlatformIcon(connection.platform)}
                    </span>
                    <div>
                      <div className="font-medium text-gray-900">{connection.name}</div>
                      <div className="text-sm text-gray-500">
                        {connection.platform.charAt(0).toUpperCase() + connection.platform.slice(1)}
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                      connection.is_active 
                        ? 'bg-green-100 text-green-800' 
                        : 'bg-red-100 text-red-800'
                    }`}>
                      {connection.is_active ? 'Active' : 'Inactive'}
                    </span>
                    
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        testConnectionMutation.mutate(connection.id);
                      }}
                      className="text-blue-600 hover:text-blue-800"
                      disabled={testConnectionMutation.isPending}
                    >
                      <PlayIcon className="h-4 w-4" />
                    </button>
                  </div>
                </div>
                
                {connection.last_sync && (
                  <div className="mt-2 text-sm text-gray-500">
                    Last sync: {new Date(connection.last_sync).toLocaleString()}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h4 className="text-md font-semibold text-gray-900 mb-3">Recent Activity</h4>
        <div className="space-y-2">
          <div className="flex items-center text-sm text-gray-600">
            <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
            {edrStats.last_24h_indicators || 0} indicators extracted in last 24 hours
          </div>
          <div className="flex items-center text-sm text-gray-600">
            <div className="w-2 h-2 bg-blue-500 rounded-full mr-2"></div>
            {edrStats.last_24h_analyses || 0} indicators analyzed by LLM
          </div>
          <div className="flex items-center text-sm text-gray-600">
            <div className="w-2 h-2 bg-purple-500 rounded-full mr-2"></div>
            ${edrStats.total_llm_cost?.toFixed(2) || '0.00'} total LLM cost
          </div>
        </div>
      </div>

      {/* Insights */}
      <div className="mt-6 bg-blue-50 rounded-lg p-4">
        <h4 className="font-medium text-blue-900 mb-2">💡 Insights</h4>
        <div className="text-sm text-blue-800 space-y-1">
          {edrStats.unknown_indicators > 0 && (
            <div>• {edrStats.unknown_indicators} indicators require LLM analysis</div>
          )}
          {edrStats.malicious_indicators > 0 && (
            <div>• {edrStats.malicious_indicators} indicators flagged as malicious</div>
          )}
          {edrStats.total_connections > 0 && (
            <div>• {edrStats.active_connections}/{edrStats.total_connections} connections active</div>
          )}
          {edrStats.total_llm_cost > 0 && (
            <div>• LLM analysis cost: ${edrStats.total_llm_cost.toFixed(2)}</div>
          )}
        </div>
      </div>
    </div>
  );
};
