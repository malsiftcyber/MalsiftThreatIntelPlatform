import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { 
  PlusIcon, 
  TrashIcon, 
  EyeIcon, 
  EyeSlashIcon,
  DocumentArrowUpIcon,
  PlayIcon,
  MagnifyingGlassIcon
} from '@heroicons/react/24/outline';
import { api, endpoints } from '../services/api';
import toast from 'react-hot-toast';

interface Exclusion {
  id: number;
  indicator_type: string;
  value: string;
  pattern_type: string;
  reason: string;
  excluded_by: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

interface ExclusionStats {
  total_exclusions: number;
  active_exclusions: number;
  exclusions_by_type: Record<string, number>;
  exclusions_by_pattern: Record<string, number>;
}

export default function Exclusions() {
  const [showAddModal, setShowAddModal] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [selectedType, setSelectedType] = useState('');
  const [selectedPatternType, setSelectedPatternType] = useState('');
  const [testPattern, setTestPattern] = useState('');
  const [testPatternType, setTestPatternType] = useState('exact');
  const [testIndicatorType, setTestIndicatorType] = useState('');
  const [testResults, setTestResults] = useState<any>(null);
  const [importFile, setImportFile] = useState<File | null>(null);
  const queryClient = useQueryClient();

  const { data: exclusions, isLoading } = useQuery('exclusions', () =>
    api.get(endpoints.exclusions, {
      params: {
        indicator_type: selectedType || undefined,
        pattern_type: selectedPatternType || undefined,
        limit: 1000,
      },
    })
  );

  const { data: stats } = useQuery('exclusion-stats', () =>
    api.get(endpoints.exclusionsStats)
  );

  const createExclusionMutation = useMutation(
    (data: any) => api.post(endpoints.exclusions, data),
    {
      onSuccess: () => {
        toast.success('Exclusion created successfully');
        queryClient.invalidateQueries('exclusions');
        queryClient.invalidateQueries('exclusion-stats');
        setShowAddModal(false);
      },
      onError: () => {
        toast.error('Failed to create exclusion');
      },
    }
  );

  const updateExclusionMutation = useMutation(
    ({ id, data }: { id: number; data: any }) => api.put(`${endpoints.exclusions}/${id}`, data),
    {
      onSuccess: () => {
        toast.success('Exclusion updated successfully');
        queryClient.invalidateQueries('exclusions');
      },
      onError: () => {
        toast.error('Failed to update exclusion');
      },
    }
  );

  const deleteExclusionMutation = useMutation(
    (id: number) => api.delete(`${endpoints.exclusions}/${id}`),
    {
      onSuccess: () => {
        toast.success('Exclusion deleted successfully');
        queryClient.invalidateQueries('exclusions');
        queryClient.invalidateQueries('exclusion-stats');
      },
      onError: () => {
        toast.error('Failed to delete exclusion');
      },
    }
  );

  const toggleExclusionMutation = useMutation(
    (id: number) => api.post(endpoints.exclusionsToggle(id)),
    {
      onSuccess: () => {
        toast.success('Exclusion toggled successfully');
        queryClient.invalidateQueries('exclusions');
        queryClient.invalidateQueries('exclusion-stats');
      },
      onError: () => {
        toast.error('Failed to toggle exclusion');
      },
    }
  );

  const testPatternMutation = useMutation(
    () => api.post(endpoints.exclusionsTest, null, {
      params: {
        pattern: testPattern,
        pattern_type: testPatternType,
        indicator_type: testIndicatorType || undefined,
      },
    }),
    {
      onSuccess: (response) => {
        setTestResults(response.data);
        toast.success(`Pattern test completed. Found ${response.data.total_matches} matches.`);
      },
      onError: () => {
        toast.error('Failed to test pattern');
      },
    }
  );

  const importExclusionsMutation = useMutation(
    (file: File) => {
      const formData = new FormData();
      formData.append('file', file);
      return api.post(endpoints.exclusionsImport, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
    },
    {
      onSuccess: (response) => {
        toast.success(`Imported ${response.data.exclusions.length} exclusions`);
        queryClient.invalidateQueries('exclusions');
        queryClient.invalidateQueries('exclusion-stats');
        setShowImportModal(false);
        setImportFile(null);
      },
      onError: () => {
        toast.error('Failed to import exclusions');
      },
    }
  );

  const handleCreateExclusion = (formData: any) => {
    createExclusionMutation.mutate(formData);
  };

  const handleTestPattern = () => {
    if (!testPattern) {
      toast.error('Please enter a pattern to test');
      return;
    }
    testPatternMutation.mutate();
  };

  const handleImportFile = () => {
    if (!importFile) {
      toast.error('Please select a file to import');
      return;
    }
    importExclusionsMutation.mutate(importFile);
  };

  const getStatusColor = (isActive: boolean) => {
    return isActive ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800';
  };

  const getPatternTypeColor = (patternType: string) => {
    const colors = {
      exact: 'bg-blue-100 text-blue-800',
      regex: 'bg-purple-100 text-purple-800',
      wildcard: 'bg-orange-100 text-orange-800',
    };
    return colors[patternType as keyof typeof colors] || colors.exact;
  };

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-900">Indicator Exclusions</h1>
        <p className="mt-2 text-sm text-gray-700">
          Manage exclusions to filter out specific indicators from API responses
        </p>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <EyeSlashIcon className="h-6 w-6 text-gray-400" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">
                    Total Exclusions
                  </dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {stats?.data?.total_exclusions || 0}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <EyeIcon className="h-6 w-6 text-gray-400" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">
                    Active Exclusions
                  </dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {stats?.data?.active_exclusions || 0}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <PlayIcon className="h-6 w-6 text-gray-400" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">
                    Pattern Types
                  </dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {Object.keys(stats?.data?.exclusions_by_pattern || {}).length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <MagnifyingGlassIcon className="h-6 w-6 text-gray-400" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">
                    Indicator Types
                  </dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {Object.keys(stats?.data?.exclusions_by_type || {}).length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="bg-white shadow rounded-lg mb-6">
        <div className="px-6 py-4">
          <div className="flex justify-between items-center">
            <div className="flex space-x-2">
              <button
                onClick={() => setShowAddModal(true)}
                className="bg-indigo-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
              >
                <PlusIcon className="h-4 w-4 inline mr-2" />
                Add Exclusion
              </button>
              <button
                onClick={() => setShowTestModal(true)}
                className="bg-green-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
              >
                <PlayIcon className="h-4 w-4 inline mr-2" />
                Test Pattern
              </button>
              <button
                onClick={() => setShowImportModal(true)}
                className="bg-purple-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500"
              >
                <DocumentArrowUpIcon className="h-4 w-4 inline mr-2" />
                Import
              </button>
            </div>
            <div className="flex space-x-2">
              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                className="border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
              >
                <option value="">All Types</option>
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="hash">Hash</option>
                <option value="email">Email</option>
                <option value="cve">CVE</option>
                <option value="all">All</option>
              </select>
              <select
                value={selectedPatternType}
                onChange={(e) => setSelectedPatternType(e.target.value)}
                className="border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
              >
                <option value="">All Patterns</option>
                <option value="exact">Exact</option>
                <option value="regex">Regex</option>
                <option value="wildcard">Wildcard</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Exclusions Table */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">
            Exclusions ({exclusions?.data?.items?.length || 0})
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Value/Pattern
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Pattern Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Reason
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Created By
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-4 text-center text-gray-500">
                    Loading...
                  </td>
                </tr>
              ) : exclusions?.data?.items?.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-4 text-center text-gray-500">
                    No exclusions found
                  </td>
                </tr>
              ) : (
                exclusions?.data?.items?.map((exclusion: Exclusion) => (
                  <tr key={exclusion.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        {exclusion.indicator_type.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <div className="max-w-xs truncate" title={exclusion.value}>
                        {exclusion.value}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getPatternTypeColor(exclusion.pattern_type)}`}>
                        {exclusion.pattern_type}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      <div className="max-w-xs truncate" title={exclusion.reason}>
                        {exclusion.reason || '-'}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(exclusion.is_active)}`}>
                        {exclusion.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {exclusion.excluded_by}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        <button
                          onClick={() => toggleExclusionMutation.mutate(exclusion.id)}
                          className="text-indigo-600 hover:text-indigo-900"
                          title={exclusion.is_active ? 'Deactivate' : 'Activate'}
                        >
                          {exclusion.is_active ? <EyeSlashIcon className="h-4 w-4" /> : <EyeIcon className="h-4 w-4" />}
                        </button>
                        <button
                          onClick={() => deleteExclusionMutation.mutate(exclusion.id)}
                          className="text-red-600 hover:text-red-900"
                          title="Delete"
                        >
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Exclusion Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Add Exclusion</h3>
              <form onSubmit={(e) => {
                e.preventDefault();
                const formData = new FormData(e.currentTarget);
                handleCreateExclusion({
                  indicator_type: formData.get('indicator_type'),
                  value: formData.get('value'),
                  pattern_type: formData.get('pattern_type'),
                  reason: formData.get('reason'),
                  excluded_by: formData.get('excluded_by') || 'admin',
                });
              }}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      Indicator Type
                    </label>
                    <select
                      name="indicator_type"
                      required
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    >
                      <option value="all">All Types</option>
                      <option value="ip">IP Address</option>
                      <option value="domain">Domain</option>
                      <option value="url">URL</option>
                      <option value="hash">Hash</option>
                      <option value="email">Email</option>
                      <option value="cve">CVE</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      Value/Pattern
                    </label>
                    <input
                      type="text"
                      name="value"
                      required
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                      placeholder="e.g., 192.168.1.1 or *.example.com"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      Pattern Type
                    </label>
                    <select
                      name="pattern_type"
                      required
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    >
                      <option value="exact">Exact Match</option>
                      <option value="regex">Regular Expression</option>
                      <option value="wildcard">Wildcard</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      Reason
                    </label>
                    <textarea
                      name="reason"
                      rows={3}
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                      placeholder="Reason for exclusion"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      Created By
                    </label>
                    <input
                      type="text"
                      name="excluded_by"
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                      placeholder="admin"
                    />
                  </div>
                </div>
                <div className="flex justify-end space-x-2 mt-6">
                  <button
                    type="button"
                    onClick={() => setShowAddModal(false)}
                    className="bg-gray-300 text-gray-700 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-400"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="bg-indigo-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-indigo-700"
                  >
                    Add Exclusion
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Test Pattern Modal */}
      {showTestModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Test Pattern</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Pattern
                  </label>
                  <input
                    type="text"
                    value={testPattern}
                    onChange={(e) => setTestPattern(e.target.value)}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    placeholder="Enter pattern to test"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Pattern Type
                  </label>
                  <select
                    value={testPatternType}
                    onChange={(e) => setTestPatternType(e.target.value)}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  >
                    <option value="exact">Exact Match</option>
                    <option value="regex">Regular Expression</option>
                    <option value="wildcard">Wildcard</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Indicator Type (Optional)
                  </label>
                  <select
                    value={testIndicatorType}
                    onChange={(e) => setTestIndicatorType(e.target.value)}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  >
                    <option value="">All Types</option>
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain</option>
                    <option value="url">URL</option>
                    <option value="hash">Hash</option>
                    <option value="email">Email</option>
                    <option value="cve">CVE</option>
                  </select>
                </div>
                {testResults && (
                  <div className="bg-gray-50 p-4 rounded-md">
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Test Results</h4>
                    <p className="text-sm text-gray-600">
                      Found {testResults.total_matches} matches
                    </p>
                    {testResults.matches.length > 0 && (
                      <div className="mt-2 max-h-32 overflow-y-auto">
                        {testResults.matches.slice(0, 5).map((match: any, index: number) => (
                          <div key={index} className="text-xs text-gray-500">
                            {match.value} ({match.indicator_type})
                          </div>
                        ))}
                        {testResults.matches.length > 5 && (
                          <div className="text-xs text-gray-500">
                            ... and {testResults.matches.length - 5} more
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
                <div className="flex justify-end space-x-2">
                  <button
                    type="button"
                    onClick={() => {
                      setShowTestModal(false);
                      setTestResults(null);
                    }}
                    className="bg-gray-300 text-gray-700 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-400"
                  >
                    Close
                  </button>
                  <button
                    type="button"
                    onClick={handleTestPattern}
                    className="bg-green-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-green-700"
                  >
                    Test Pattern
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Import Modal */}
      {showImportModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Import Exclusions</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    File (CSV or JSON)
                  </label>
                  <input
                    type="file"
                    accept=".csv,.json"
                    onChange={(e) => setImportFile(e.target.files?.[0] || null)}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  />
                </div>
                <div className="bg-gray-50 p-4 rounded-md">
                  <h4 className="text-sm font-medium text-gray-900 mb-2">File Format</h4>
                  <p className="text-xs text-gray-600 mb-2">
                    <strong>CSV:</strong> indicator_type,value,pattern_type,reason,excluded_by
                  </p>
                  <p className="text-xs text-gray-600">
                    <strong>JSON:</strong> Array of objects with indicator_type, value, pattern_type, reason, excluded_by
                  </p>
                </div>
                <div className="flex justify-end space-x-2">
                  <button
                    type="button"
                    onClick={() => {
                      setShowImportModal(false);
                      setImportFile(null);
                    }}
                    className="bg-gray-300 text-gray-700 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-400"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={handleImportFile}
                    className="bg-purple-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-purple-700"
                  >
                    Import
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
