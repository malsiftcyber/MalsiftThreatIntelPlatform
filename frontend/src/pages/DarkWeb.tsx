import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { PlayIcon, EyeIcon } from '@heroicons/react/24/outline';
import { api, endpoints } from '../services/api';
import toast from 'react-hot-toast';

interface DarkWebSource {
  id: number;
  name: string;
  url: string;
  description: string;
  is_active: boolean;
  requires_tor: boolean;
  last_scrape: string;
  scrape_interval_hours: number;
}

export default function DarkWeb() {
  const [showAddModal, setShowAddModal] = useState(false);
  const queryClient = useQueryClient();

  const { data: sources, isLoading } = useQuery('darkweb-sources', () =>
    api.get(endpoints.darkweb)
  );

  const { data: status } = useQuery('darkweb-status', () =>
    api.get(endpoints.darkwebStatus)
  );

  const scrapeAllMutation = useMutation(
    () => api.post(endpoints.darkwebScrapeAll),
    {
      onSuccess: () => {
        toast.success('Started scraping all dark web sources');
      },
      onError: () => {
        toast.error('Failed to start dark web scraping');
      },
    }
  );

  const scrapeSourceMutation = useMutation(
    (sourceId: number) => api.post(`${endpoints.darkweb}/${sourceId}/scrape`),
    {
      onSuccess: () => {
        toast.success('Started scraping source');
      },
      onError: () => {
        toast.error('Failed to start scraping');
      },
    }
  );

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-900">Dark Web Monitoring</h1>
        <p className="mt-2 text-sm text-gray-700">
          Monitor and scrape dark web sources for threat intelligence
        </p>
      </div>

      {/* Status Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <EyeIcon className="h-6 w-6 text-gray-400" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">
                    Total Sources
                  </dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {status?.data?.total_sources || 0}
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
                    Active Sources
                  </dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {status?.data?.active_sources || 0}
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
                    Last Scrape
                  </dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {status?.data?.recent_scrapes?.[0]?.last_scrape ? 
                      new Date(status.data.recent_scrapes[0].last_scrape).toLocaleDateString() : 
                      'Never'
                    }
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
                Add Source
              </button>
              <button
                onClick={() => scrapeAllMutation.mutate()}
                disabled={scrapeAllMutation.isLoading}
                className="bg-green-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50"
              >
                <PlayIcon className="h-4 w-4 inline mr-2" />
                {scrapeAllMutation.isLoading ? 'Starting...' : 'Scrape All Sources'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Sources Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        {sources?.data?.map((source: DarkWebSource) => (
          <div key={source.id} className="bg-white shadow rounded-lg">
            <div className="px-6 py-4 border-b border-gray-200">
              <div className="flex justify-between items-center">
                <h3 className="text-lg font-medium text-gray-900">
                  {source.name}
                </h3>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => scrapeSourceMutation.mutate(source.id)}
                    disabled={scrapeSourceMutation.isLoading}
                    className="text-indigo-600 hover:text-indigo-900"
                    title="Scrape now"
                  >
                    <PlayIcon className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
            <div className="px-6 py-4">
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">Status:</span>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    source.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {source.is_active ? 'Active' : 'Inactive'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">Tor Required:</span>
                  <span className="text-sm text-gray-900">
                    {source.requires_tor ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">Last Scrape:</span>
                  <span className="text-sm text-gray-900">
                    {source.last_scrape ? new Date(source.last_scrape).toLocaleDateString() : 'Never'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">Interval:</span>
                  <span className="text-sm text-gray-900">
                    {source.scrape_interval_hours}h
                  </span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Recent Activity */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Recent Scraping Activity</h3>
        </div>
        <div className="p-6">
          <div className="space-y-4">
            {status?.data?.recent_scrapes?.map((scrape: any, index: number) => (
              <div key={index} className="flex justify-between items-center">
                <div>
                  <span className="text-sm font-medium text-gray-900">{scrape.name}</span>
                  <span className="text-sm text-gray-500 ml-2">
                    {new Date(scrape.last_scrape).toLocaleString()}
                  </span>
                </div>
                <span className="text-sm text-gray-500">
                  Every {scrape.scrape_interval_hours}h
                </span>
              </div>
            ))}
            {(!status?.data?.recent_scrapes || status.data.recent_scrapes.length === 0) && (
              <div className="text-center text-gray-500">
                <p>No recent scraping activity</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Add Source Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Add Dark Web Source</h3>
              <form className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Source Name
                  </label>
                  <input
                    type="text"
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    placeholder="e.g., Example Forum"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    URL
                  </label>
                  <input
                    type="url"
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    placeholder="http://example.onion"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Description
                  </label>
                  <textarea
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    rows={3}
                    placeholder="Description of the source"
                  />
                </div>
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                  />
                  <label className="ml-2 block text-sm text-gray-900">
                    Requires Tor
                  </label>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Scrape Interval (hours)
                  </label>
                  <input
                    type="number"
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    defaultValue={24}
                    min={1}
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
                    Add Source
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
