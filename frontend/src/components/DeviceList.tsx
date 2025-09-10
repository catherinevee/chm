import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import apiService, { Device, DeviceListResponse } from '../services/api';
import CsvUpload from './CsvUpload';
import AddDeviceModal from './AddDeviceModal';
import CsvPasteModal from './CsvPasteModal';
import EditDeviceModal from './EditDeviceModal';

interface DeviceListProps {
  onDeviceSelect?: (device: Device) => void;
}

const DeviceList: React.FC<DeviceListProps> = ({ onDeviceSelect }) => {
  const navigate = useNavigate();
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ message: string; severity: 'success' | 'error' | 'warning' | 'info' } | null>(null);
  
  // Pagination state
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 50,
    total: 0,
    pages: 0
  });
  
  // Filter state
  const [filters, setFilters] = useState({
    search: '',
    device_type: '',
    status: '',
    group: '',
    location: '',
    manufacturer: ''
  });
  
  // Sorting state
  const [sortConfig, setSortConfig] = useState<{
    key: keyof Device | null;
    direction: 'asc' | 'desc';
  }>({
    key: null,
    direction: 'asc'
  });
  
        // Dialog state
      const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
      const [detailDialogOpen, setDetailDialogOpen] = useState(false);
      const [showCsvUpload, setShowCsvUpload] = useState(false);
      const [showAddDevice, setShowAddDevice] = useState(false);
      const [showCsvPaste, setShowCsvPaste] = useState(false);
      const [showEditDevice, setShowEditDevice] = useState(false);
      const [deviceToEdit, setDeviceToEdit] = useState<Device | null>(null);
      const [deviceToDelete, setDeviceToDelete] = useState<Device | null>(null);
      const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  const fetchDevices = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const params = {
        page: pagination.page,
        limit: pagination.limit,
        ...filters
      };
      
      const response: DeviceListResponse = await apiService.getDevices(params);
      setDevices(response.devices);
      setPagination(response.pagination);
    } catch (err) {
      console.error('Error fetching devices:', err);
      setError('Failed to fetch devices. Please try again.');
      setNotification({
        message: 'Failed to fetch devices. Please try again.',
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDevices();
  }, [pagination.page, filters]);

  const handleFilterChange = (field: string, value: string) => {
    setFilters(prev => ({ ...prev, [field]: value }));
    setPagination(prev => ({ ...prev, page: 1 })); // Reset to first page when filtering
  };

  const handlePageChange = (page: number) => {
    setPagination(prev => ({ ...prev, page }));
  };

  const handleDeviceSelect = (device: Device) => {
    if (onDeviceSelect) {
      onDeviceSelect(device);
    }
  };

  const handleDeviceClick = (device: Device) => {
    navigate(`/device/${device.id}`);
  };

  const handleSort = (key: keyof Device) => {
    let direction: 'asc' | 'desc' = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  const getSortIcon = (columnKey: keyof Device) => {
    if (sortConfig.key !== columnKey) {
      return (
        <svg className="w-4 h-4 ml-1 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
        </svg>
      );
    }
    
    if (sortConfig.direction === 'asc') {
      return (
        <svg className="w-4 h-4 ml-1 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16V4m0 0L3 8m4-4l4 4" />
        </svg>
      );
    } else {
      return (
        <svg className="w-4 h-4 ml-1 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 8V20m0 0l4-4m-4 4l-4-4" />
        </svg>
      );
    }
  };

  const sortedDevices = React.useMemo(() => {
    if (!sortConfig.key) return devices;
    
    return [...devices].sort((a, b) => {
      const aValue = a[sortConfig.key!];
      const bValue = b[sortConfig.key!];
      
      if (aValue === null || aValue === undefined) return 1;
      if (bValue === null || bValue === undefined) return -1;
      
      if (aValue < bValue) {
        return sortConfig.direction === 'asc' ? -1 : 1;
      }
      if (aValue > bValue) {
        return sortConfig.direction === 'asc' ? 1 : -1;
      }
      return 0;
    });
  }, [devices, sortConfig]);

  const handleViewDetails = (device: Device) => {
    setSelectedDevice(device);
    setDetailDialogOpen(true);
  };

  const handleRefresh = () => {
    fetchDevices();
    setNotification({
      message: 'Device list refreshed successfully.',
      severity: 'success'
    });
  };

  const [showExportOptions, setShowExportOptions] = useState(false);

  const handleExport = async (format: string = 'csv') => {
    try {
      const exportData = await apiService.exportData({
        data_type: 'devices',
        format: format,
        filters
      });
      
      // Create and download file
      let blob: Blob;
      let mimeType: string;
      
      if (format === 'csv') {
        blob = new Blob([exportData.data], { type: 'text/csv' });
        mimeType = 'text/csv';
      } else if (format === 'json') {
        blob = new Blob([JSON.stringify(exportData.data, null, 2)], { type: 'application/json' });
        mimeType = 'application/json';
      } else if (format === 'excel') {
        blob = new Blob([exportData.data], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
        mimeType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
      } else {
        throw new Error('Unsupported export format');
      }
      
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = exportData.filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      setNotification({
        message: `Device data exported successfully as ${format.toUpperCase()}.`,
        severity: 'success'
      });
      setShowExportOptions(false);
    } catch (err) {
      console.error('Error exporting data:', err);
      setNotification({
        message: 'Failed to export data. Please try again.',
        severity: 'error'
      });
    }
  };

        const handleCsvUploadComplete = () => {
        setShowCsvUpload(false);
        fetchDevices();
        setNotification({
          message: 'Devices imported successfully. Device list refreshed.',
          severity: 'success'
        });
      };

      const handleDeviceAdded = () => {
        fetchDevices();
        setNotification({
          message: 'Device added successfully. Device list refreshed.',
          severity: 'success'
        });
      };

      const handleCsvPasteComplete = () => {
        setShowCsvPaste(false);
        fetchDevices();
        setNotification({
          message: 'CSV data imported successfully. Device list refreshed.',
          severity: 'success'
        });
      };

      const handleDeviceUpdated = () => {
        setShowEditDevice(false);
        setDeviceToEdit(null);
        fetchDevices();
        setNotification({
          message: 'Device updated successfully. Device list refreshed.',
          severity: 'success'
        });
      };

      const handleEditDevice = (device: Device) => {
        setDeviceToEdit(device);
        setShowEditDevice(true);
      };

      const handleDeleteDevice = (device: Device) => {
        setDeviceToDelete(device);
        setShowDeleteConfirm(true);
      };

      const confirmDeleteDevice = async () => {
        if (!deviceToDelete) return;

        try {
          await apiService.deleteDevice(deviceToDelete.id);
          setShowDeleteConfirm(false);
          setDeviceToDelete(null);
          fetchDevices();
          setNotification({
            message: 'Device deleted successfully. Device list refreshed.',
            severity: 'success'
          });
        } catch (err: any) {
          setNotification({
            message: err.response?.data?.detail || 'Failed to delete device.',
            severity: 'error'
          });
        }
      };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return 'badge-success';
      case 'offline':
        return 'badge-error';
      case 'maintenance':
        return 'badge-warning';
      case 'decommissioned':
        return 'badge-neutral';
      default:
        return 'badge-neutral';
    }
  };

  const getDeviceTypeColor = (type: string) => {
    switch (type) {
      case 'router':
        return 'badge-primary';
      case 'switch':
        return 'badge-secondary';
      case 'firewall':
        return 'badge-error';
      case 'server':
        return 'badge-info';
      default:
        return 'badge-neutral';
    }
  };

  if (loading && devices.length === 0) {
    return (
      <div className="flex justify-center items-center min-h-96">
        <span className="loading loading-spinner loading-lg"></span>
      </div>
    );
  }

  return (
    <div>
      {/* Header with actions */}
      <div className="card bg-base-200 shadow-lg mb-6">
        <div className="card-body">
          <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
            <div>
              <h2 className="card-title text-2xl">Device Inventory</h2>
              <p className="text-base-content/70">
                {pagination.total} devices found
              </p>
            </div>
            <div className="flex gap-2">
              <button
                className="btn btn-outline"
                onClick={handleRefresh}
                disabled={loading}
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                Refresh
              </button>
                                <div className="dropdown dropdown-end">
                    <button
                      className="btn btn-outline"
                      onClick={() => setShowExportOptions(!showExportOptions)}
                      disabled={loading}
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      Export
                    </button>
                    {showExportOptions && (
                      <ul className="dropdown-content menu p-2 shadow bg-base-100 rounded-box w-52">
                        <li><button onClick={() => handleExport('csv')}>Export as CSV</button></li>
                        <li><button onClick={() => handleExport('json')}>Export as JSON</button></li>
                        <li><button onClick={() => handleExport('excel')}>Export as Excel</button></li>
                      </ul>
                    )}
                  </div>
                  <button
                    className="btn btn-outline"
                    onClick={() => setShowCsvUpload(true)}
                    disabled={loading}
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                    Upload CSV
                  </button>
                  <button
                    className="btn btn-outline"
                    onClick={() => setShowCsvPaste(true)}
                    disabled={loading}
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    Paste CSV
                  </button>
                  <button 
                    className="btn btn-primary"
                    onClick={() => setShowAddDevice(true)}
                    disabled={loading}
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                    </svg>
                    Add Device
                  </button>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="card bg-base-200 shadow-lg mb-6">
        <div className="card-body">
          <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
            <div className="form-control">
              <label className="label">
                <span className="label-text">Search</span>
              </label>
              <div className="input-group">
                <span className="btn btn-square btn-ghost">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                </span>
                <input
                  type="text"
                  className="input input-bordered w-full"
                  placeholder="Hostname, IP, Serial..."
                  value={filters.search}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleFilterChange('search', e.target.value)}
                />
              </div>
            </div>
            <div className="form-control">
              <label className="label">
                <span className="label-text">Device Type</span>
              </label>
              <select
                className="select select-bordered w-full"
                value={filters.device_type}
                onChange={(e: React.ChangeEvent<HTMLSelectElement>) => handleFilterChange('device_type', e.target.value)}
              >
                <option value="">All Types</option>
                <option value="router">Router</option>
                <option value="switch">Switch</option>
                <option value="firewall">Firewall</option>
                <option value="server">Server</option>
                <option value="workstation">Workstation</option>
              </select>
            </div>
            <div className="form-control">
              <label className="label">
                <span className="label-text">Status</span>
              </label>
              <select
                className="select select-bordered w-full"
                value={filters.status}
                onChange={(e: React.ChangeEvent<HTMLSelectElement>) => handleFilterChange('status', e.target.value)}
              >
                <option value="">All Status</option>
                <option value="online">Online</option>
                <option value="offline">Offline</option>
                <option value="maintenance">Maintenance</option>
                <option value="decommissioned">Decommissioned</option>
              </select>
            </div>
            <div className="form-control">
              <label className="label">
                <span className="label-text">Group</span>
              </label>
              <select
                className="select select-bordered w-full"
                value={filters.group}
                onChange={(e: React.ChangeEvent<HTMLSelectElement>) => handleFilterChange('group', e.target.value)}
              >
                <option value="">All Groups</option>
                <option value="production">Production</option>
                <option value="development">Development</option>
                <option value="testing">Testing</option>
                <option value="dmz">DMZ</option>
                <option value="internal">Internal</option>
              </select>
            </div>
            <div className="form-control">
              <label className="label">
                <span className="label-text">Location</span>
              </label>
              <input
                type="text"
                className="input input-bordered"
                placeholder="Data center, building..."
                value={filters.location}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleFilterChange('location', e.target.value)}
              />
            </div>
            <div className="form-control">
              <label className="label">
                <span className="label-text">Manufacturer</span>
              </label>
              <input
                type="text"
                className="input input-bordered"
                placeholder="Cisco, HP, Dell..."
                value={filters.manufacturer}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleFilterChange('manufacturer', e.target.value)}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="alert alert-error mb-6">
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>{error}</span>
          <button className="btn btn-sm btn-ghost" onClick={() => setError(null)}>×</button>
        </div>
      )}

      {/* Device Table */}
      <div className="card bg-base-100 shadow-lg">
        <div className="overflow-x-auto">
          <table className="table table-zebra w-full">
            <thead>
              <tr>
                <th 
                  className="cursor-pointer hover:bg-base-200 select-none"
                  onClick={() => handleSort('hostname')}
                >
                  <div className="flex items-center">
                    Hostname
                    {getSortIcon('hostname')}
                  </div>
                </th>
                <th 
                  className="cursor-pointer hover:bg-base-200 select-none"
                  onClick={() => handleSort('ip_address')}
                >
                  <div className="flex items-center">
                    IP Address
                    {getSortIcon('ip_address')}
                  </div>
                </th>
                <th 
                  className="cursor-pointer hover:bg-base-200 select-none"
                  onClick={() => handleSort('device_type')}
                >
                  <div className="flex items-center">
                    Type
                    {getSortIcon('device_type')}
                  </div>
                </th>
                <th 
                  className="cursor-pointer hover:bg-base-200 select-none"
                  onClick={() => handleSort('current_state')}
                >
                  <div className="flex items-center">
                    Status
                    {getSortIcon('current_state')}
                  </div>
                </th>
                <th 
                  className="cursor-pointer hover:bg-base-200 select-none"
                  onClick={() => handleSort('location')}
                >
                  <div className="flex items-center">
                    Location
                    {getSortIcon('location')}
                  </div>
                </th>
                <th 
                  className="cursor-pointer hover:bg-base-200 select-none"
                  onClick={() => handleSort('asset_tag')}
                >
                  <div className="flex items-center">
                    Asset Tag
                    {getSortIcon('asset_tag')}
                  </div>
                </th>
                <th 
                  className="cursor-pointer hover:bg-base-200 select-none"
                  onClick={() => handleSort('last_poll_time')}
                >
                  <div className="flex items-center">
                    Last Poll
                    {getSortIcon('last_poll_time')}
                  </div>
                </th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sortedDevices.map((device) => (
                <tr 
                  key={device.id}
                  className="hover"
                >
                  <td>
                    <div>
                      <div 
                        className="font-bold text-primary cursor-pointer hover:underline"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDeviceClick(device);
                        }}
                        title="Click to view device details and graphs"
                      >
                        {device.hostname}
                      </div>
                      {device.serial_number && (
                        <div className="text-sm opacity-50">S/N: {device.serial_number}</div>
                      )}
                    </div>
                  </td>
                  <td>{device.ip_address}</td>
                  <td>
                    <span className={`badge ${getDeviceTypeColor(device.device_type)}`}>
                      {device.device_type}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${getStatusColor(device.current_state)}`}>
                      {device.current_state}
                    </span>
                  </td>
                  <td>
                    <div>
                      {device.location || '-'}
                      {device.rack_position && (
                        <div className="text-sm opacity-50">Rack: {device.rack_position}</div>
                      )}
                    </div>
                  </td>
                  <td>{device.asset_tag || '-'}</td>
                  <td>
                    {device.last_poll_time 
                      ? new Date(device.last_poll_time).toLocaleString()
                      : 'Never'
                    }
                  </td>
                  <td>
                    <div className="flex gap-1">
                      <button
                        className="btn btn-sm btn-ghost"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleViewDetails(device);
                        }}
                        title="View Details"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                        </svg>
                      </button>
                                             <button 
                         className="btn btn-sm btn-ghost" 
                         title="Edit Device"
                         onClick={(e) => {
                           e.stopPropagation();
                           handleEditDevice(device);
                         }}
                       >
                         <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                           <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                         </svg>
                       </button>
                       <button 
                         className="btn btn-sm btn-ghost text-error" 
                         title="Delete Device"
                         onClick={(e) => {
                           e.stopPropagation();
                           handleDeleteDevice(device);
                         }}
                       >
                         <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                           <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                         </svg>
                       </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        {/* Pagination */}
        {pagination.pages > 1 && (
          <div className="flex justify-center p-4">
            <div className="join">
              {Array.from({ length: pagination.pages }, (_, i) => i + 1).map((page) => (
                <button
                  key={page}
                  className={`join-item btn ${page === pagination.page ? 'btn-active' : ''}`}
                  onClick={() => handlePageChange(page)}
                >
                  {page}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Device Detail Dialog */}
      {detailDialogOpen && (
        <div className="modal modal-open">
          <div className="modal-box max-w-4xl">
            <h3 className="font-bold text-lg mb-4">
              Device Details - {selectedDevice?.hostname}
            </h3>
            {selectedDevice && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-semibold mb-2">Basic Information</h4>
                  <div className="space-y-1 text-sm">
                    <div><strong>Hostname:</strong> {selectedDevice.hostname}</div>
                    <div><strong>IP Address:</strong> {selectedDevice.ip_address}</div>
                    <div><strong>Device Type:</strong> {selectedDevice.device_type}</div>
                    <div><strong>Status:</strong> {selectedDevice.current_state}</div>
                    <div><strong>Serial Number:</strong> {selectedDevice.serial_number || '-'}</div>
                    <div><strong>Model:</strong> {selectedDevice.model || '-'}</div>
                    <div><strong>Manufacturer:</strong> {selectedDevice.manufacturer || '-'}</div>
                  </div>
                </div>
                <div>
                  <h4 className="font-semibold mb-2">Asset Information</h4>
                  <div className="space-y-1 text-sm">
                    <div><strong>Asset Tag:</strong> {selectedDevice.asset_tag || '-'}</div>
                    <div><strong>Location:</strong> {selectedDevice.location || '-'}</div>
                    <div><strong>Department:</strong> {selectedDevice.department || '-'}</div>
                    <div><strong>Owner:</strong> {selectedDevice.owner || '-'}</div>
                    <div><strong>Cost:</strong> {selectedDevice.cost ? `$${selectedDevice.cost}` : '-'}</div>
                    <div><strong>Purchase Date:</strong> {selectedDevice.purchase_date ? new Date(selectedDevice.purchase_date).toLocaleDateString() : '-'}</div>
                    <div><strong>Warranty Expiry:</strong> {selectedDevice.warranty_expiry ? new Date(selectedDevice.warranty_expiry).toLocaleDateString() : '-'}</div>
                  </div>
                </div>
                {selectedDevice.hardware_components && selectedDevice.hardware_components.length > 0 && (
                  <div className="md:col-span-2">
                    <h4 className="font-semibold mb-2">Hardware Components</h4>
                    <div className="overflow-x-auto">
                      <table className="table table-sm">
                        <thead>
                          <tr>
                            <th>Type</th>
                            <th>Manufacturer</th>
                            <th>Model</th>
                            <th>Capacity</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {selectedDevice.hardware_components.map((hw) => (
                            <tr key={hw.id}>
                              <td>{hw.component_type}</td>
                              <td>{hw.manufacturer || '-'}</td>
                              <td>{hw.model || '-'}</td>
                              <td>{hw.capacity || '-'}</td>
                              <td>{hw.status}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}
            <div className="modal-action">
              <button className="btn" onClick={() => setDetailDialogOpen(false)}>Close</button>
            </div>
          </div>
        </div>
      )}

                {/* CSV Upload Modal */}
          {showCsvUpload && (
            <div className="modal modal-open">
              <div className="modal-box max-w-4xl max-h-screen overflow-y-auto">
                <CsvUpload
                  onUploadComplete={handleCsvUploadComplete}
                  onClose={() => setShowCsvUpload(false)}
                />
              </div>
            </div>
          )}

          {/* Add Device Modal */}
          <AddDeviceModal
            isOpen={showAddDevice}
            onClose={() => setShowAddDevice(false)}
            onDeviceAdded={handleDeviceAdded}
          />

                     {/* CSV Paste Modal */}
           <CsvPasteModal
             isOpen={showCsvPaste}
             onClose={() => setShowCsvPaste(false)}
             onImportComplete={handleCsvPasteComplete}
           />

           {/* Edit Device Modal */}
           <EditDeviceModal
             isOpen={showEditDevice}
             onClose={() => {
               setShowEditDevice(false);
               setDeviceToEdit(null);
             }}
             onDeviceUpdated={handleDeviceUpdated}
             device={deviceToEdit}
           />

           {/* Delete Confirmation Modal */}
           {showDeleteConfirm && deviceToDelete && (
             <div className="modal modal-open">
               <div className="modal-box">
                 <h3 className="font-bold text-lg mb-4">Confirm Delete</h3>
                 <p className="mb-4">
                   Are you sure you want to delete the device <strong>{deviceToDelete.hostname}</strong>?
                   This action cannot be undone.
                 </p>
                 <div className="modal-action">
                   <button
                     className="btn"
                     onClick={() => {
                       setShowDeleteConfirm(false);
                       setDeviceToDelete(null);
                     }}
                   >
                     Cancel
                   </button>
                   <button
                     className="btn btn-error"
                     onClick={confirmDeleteDevice}
                   >
                     Delete Device
                   </button>
                 </div>
               </div>
             </div>
           )}

           {/* Notification Toast */}
           {notification && (
             <div className={`toast toast-end ${
               notification.severity === 'error' ? 'alert-error' : 
               notification.severity === 'warning' ? 'alert-warning' : 
               'alert-success'
             }`}>
               <span>{notification.message}</span>
               <button className="btn btn-sm btn-ghost" onClick={() => setNotification(null)}>×</button>
             </div>
           )}
        </div>
      );
    };

    export default DeviceList;
