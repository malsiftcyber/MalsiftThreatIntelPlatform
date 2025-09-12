import React, { useState } from 'react';
import { useQuery } from 'react-query';
import { useTable, useFilters, useSortBy, usePagination } from 'react-table';
import { MagnifyingGlassIcon, FunnelIcon } from '@heroicons/react/24/outline';
import { api, endpoints } from '../services/api';
import { format } from 'date-fns';

interface Indicator {
  id: number;
  indicator_type: string;
  value: string;
  confidence_score: number;
  threat_level: string;
  tags: string[];
  description: string;
  first_seen: string;
  last_seen: string;
  source_id: number;
  is_active: boolean;
}

export default function Indicators() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [selectedLevel, setSelectedLevel] = useState('');

  const { data: indicatorsData, isLoading } = useQuery(
    ['indicators', searchTerm, selectedType, selectedLevel],
    () => api.get(endpoints.indicators, {
      params: {
        search: searchTerm || undefined,
        indicator_type: selectedType || undefined,
        threat_level: selectedLevel || undefined,
        limit: 1000,
      },
    })
  );

  const indicators = indicatorsData?.data?.items || [];

  const columns = React.useMemo(
    () => [
      {
        Header: 'Type',
        accessor: 'indicator_type',
        Cell: ({ value }: { value: string }) => (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
            {value.toUpperCase()}
          </span>
        ),
      },
      {
        Header: 'Value',
        accessor: 'value',
        Cell: ({ value }: { value: string }) => (
          <div className="max-w-xs truncate" title={value}>
            {value}
          </div>
        ),
      },
      {
        Header: 'Threat Level',
        accessor: 'threat_level',
        Cell: ({ value }: { value: string }) => {
          const colors = {
            low: 'bg-green-100 text-green-800',
            medium: 'bg-yellow-100 text-yellow-800',
            high: 'bg-orange-100 text-orange-800',
            critical: 'bg-red-100 text-red-800',
          };
          return (
            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colors[value as keyof typeof colors] || colors.low}`}>
              {value.charAt(0).toUpperCase() + value.slice(1)}
            </span>
          );
        },
      },
      {
        Header: 'Confidence',
        accessor: 'confidence_score',
        Cell: ({ value }: { value: number }) => (
          <span className="text-sm text-gray-900">
            {Math.round(value * 100)}%
          </span>
        ),
      },
      {
        Header: 'Tags',
        accessor: 'tags',
        Cell: ({ value }: { value: string[] }) => (
          <div className="flex flex-wrap gap-1">
            {value?.slice(0, 3).map((tag, index) => (
              <span
                key={index}
                className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800"
              >
                {tag}
              </span>
            ))}
            {value && value.length > 3 && (
              <span className="text-xs text-gray-500">+{value.length - 3}</span>
            )}
          </div>
        ),
      },
      {
        Header: 'First Seen',
        accessor: 'first_seen',
        Cell: ({ value }: { value: string }) => (
          <span className="text-sm text-gray-900">
            {format(new Date(value), 'MMM dd, yyyy')}
          </span>
        ),
      },
      {
        Header: 'Last Seen',
        accessor: 'last_seen',
        Cell: ({ value }: { value: string }) => (
          <span className="text-sm text-gray-900">
            {format(new Date(value), 'MMM dd, yyyy')}
          </span>
        ),
      },
      {
        Header: 'Status',
        accessor: 'is_active',
        Cell: ({ value }: { value: boolean }) => (
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
            value ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
          }`}>
            {value ? 'Active' : 'Inactive'}
          </span>
        ),
      },
    ],
    []
  );

  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    rows,
    prepareRow,
  } = useTable(
    {
      columns,
      data: indicators,
      initialState: { pageSize: 20 },
    },
    useFilters,
    useSortBy,
    usePagination
  );

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-900">Threat Indicators</h1>
        <p className="mt-2 text-sm text-gray-700">
          View and manage threat intelligence indicators
        </p>
      </div>

      {/* Filters */}
      <div className="bg-white shadow rounded-lg mb-6">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Filters</h3>
        </div>
        <div className="px-6 py-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Search
              </label>
              <div className="relative">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search indicators..."
                  className="pl-10 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Type
              </label>
              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                className="block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
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
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Threat Level
              </label>
              <select
                value={selectedLevel}
                onChange={(e) => setSelectedLevel(e.target.value)}
                className="block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
              >
                <option value="">All Levels</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            <div className="flex items-end">
              <button
                onClick={() => {
                  setSearchTerm('');
                  setSelectedType('');
                  setSelectedLevel('');
                }}
                className="w-full bg-gray-100 text-gray-700 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500"
              >
                Clear Filters
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-medium text-gray-900">
              Indicators ({indicators.length})
            </h3>
            <div className="flex space-x-2">
              <button className="bg-indigo-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                Export
              </button>
              <button className="bg-green-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500">
                Deduplicate
              </button>
            </div>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table {...getTableProps()} className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              {headerGroups.map(headerGroup => (
                <tr {...headerGroup.getHeaderGroupProps()}>
                  {headerGroup.headers.map(column => (
                    <th
                      {...column.getHeaderProps(column.getSortByToggleProps())}
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                    >
                      {column.render('Header')}
                      <span>
                        {column.isSorted
                          ? column.isSortedDesc
                            ? ' 🔽'
                            : ' 🔼'
                          : ''}
                      </span>
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody {...getTableBodyProps()} className="bg-white divide-y divide-gray-200">
              {isLoading ? (
                <tr>
                  <td colSpan={columns.length} className="px-6 py-4 text-center text-gray-500">
                    Loading...
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={columns.length} className="px-6 py-4 text-center text-gray-500">
                    No indicators found
                  </td>
                </tr>
              ) : (
                rows.map(row => {
                  prepareRow(row);
                  return (
                    <tr {...row.getRowProps()} className="hover:bg-gray-50">
                      {row.cells.map(cell => (
                        <td {...cell.getCellProps()} className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {cell.render('Cell')}
                        </td>
                      ))}
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
