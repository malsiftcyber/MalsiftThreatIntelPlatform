import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { PlusIcon, PlayIcon, StopIcon, CogIcon } from '@heroicons/react/24/outline';
import { api, endpoints } from '../services/api';
import toast from 'react-hot-toast';

interface FeedConfiguration {
  id: number;
  source_name: string;
  is_enabled: boolean;
  base_url: string;
  created_at: string;
  updated_at: string;
}

interface FetchJob {
  id: number;
  source_name: string;
  status: string;
  started_at: string;
  completed_at: string;
  indicators_found: number;
  indicators_new: number;
  error_message: string;
}

export default function Feeds() {
  const [showAddModal, setShowAddModal] = useState(false);
  const queryClient = useQueryClient();

  const { data: feeds, isLoading } = useQuery('feeds', () =>
    api.get(endpoints.feeds)
  );

  const { data: jobs } = useQuery('feed-jobs', () =>
    api.get(endpoints.feedsJobs)
  );

  const fetchAllMutation = useMutation(
    () => api.post(endpoints.feedsFetchAll),
    {
      onSuccess: () => {
        toast.success('Started fetching all feeds');
        queryClient.invalidateQueries('feed-jobs');
      },
      onError: () => {
        toast.error('Failed to start feed fetch');
      },
    }
  );

  const toggleFeedMutation = useMutation(
    ({ id, is_enabled }: { id: number; is_enabled: boolean }) =>
      api.put(`${endpoints.feeds}/${id}`, { is_enabled }),
    {
      onSuccess: () => {
        toast.success('Feed updated successfully');
        queryClient.invalidateQueries('feeds');
      },
      onError: () => {
        toast.error('Failed to update feed');
      },
    }
  );

  const fetchFeedMutation = useMutation(
    (configId: number) => api.post(`${endpoints.feeds}/${configId}/fetch`),
    {
      onSuccess: () => {
        toast.success('Started feed fetch');
        queryClient.invalidateQueries('feed-jobs');
      },
      onError: () => {
        toast.error('Failed to start feed fetch');
      },
    }
  );

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'running':
        return 'bg-blue-100 text-blue-800';
      case 'failed':
        return 'bg-red-100 text-red-800';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-900">Feed Management</h1>
        <p className="mt-2 text-sm text-gray-700">
          Configure and manage threat intelligence feeds
        </p>
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
                Add Feed
              </button>
              <button
                onClick={() => fetchAllMutation.mutate()}
                disabled={fetchAllMutation.isLoading}
                className="bg-green-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50"
              >
                <PlayIcon className="h-4 w-4 inline mr-2" />
                {fetchAllMutation.isLoading ? 'Starting...' : 'Fetch All Feeds'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Feeds Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        {feeds?.data?.map((feed: FeedConfiguration) => (
          <div key={feed.id} className="bg-white shadow rounded-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <div className="flex justify-between items-center">
                <h3 className="text-lg font-medium text-gray-900">
                  {feed.source_name}
                </h3>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => fetchFeedMutation.mutate(feed.id)}
                    disabled={fetchFeedMutation.isLoading}
                    className="text-indigo-600 hover:text-indigo-900"
                    title="Fetch now"
                  >
                    <PlayIcon className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => toggleFeedMutation.mutate({ id: feed.id, is_enabled: !feed.is_enabled })}
                    className={`${
                      feed.is_enabled ? 'text-green-600' : 'text-red-600'
                    } hover:text-gray-900`}
                    title={feed.is_enabled ? 'Disable feed' : 'Enable feed'}
                  >
                    <CogIcon className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
            <div className="px-6 py-4">
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">Status:</span>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    feed.is_enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {feed.is_enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">Base URL:</span>
                  <span className="text-sm text-gray-900 truncate max-w-32">
                    {feed.base_url}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">Updated:</span>
                  <span className="text-sm text-gray-900">
                    {new Date(feed.updated_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Recent Jobs */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Recent Fetch Jobs</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Source
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Started
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Completed
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Found
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  New
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {jobs?.data?.slice(0, 10).map((job: FetchJob) => (
                <tr key={job.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                    {job.source_name}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(job.status)}`}>
                      {job.status.charAt(0).toUpperCase() + job.status.slice(1)}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {job.started_at ? new Date(job.started_at).toLocaleString() : '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {job.completed_at ? new Date(job.completed_at).toLocaleString() : '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {job.indicators_found}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {job.indicators_new}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Feed Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Add New Feed</h3>
              <form className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Source Name
                  </label>
                  <input
                    type="text"
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    placeholder="e.g., CISA, OTX, VirusTotal"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Base URL
                  </label>
                  <input
                    type="url"
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    placeholder="https://api.example.com"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    API Key (optional)
                  </label>
                  <input
                    type="password"
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    placeholder="Enter API key if required"
                  />
                </div>
                <div className="flex justify-end space-x-2">
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
                    Add Feed
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
