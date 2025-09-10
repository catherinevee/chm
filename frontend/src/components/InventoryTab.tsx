import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import apiService, { Asset, AssetListResponse, CapacityData } from '../services/api';

const InventoryTab: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ message: string; severity: 'success' | 'error' | 'warning' | 'info' } | null>(null);
  
  // Asset Management State
  const [assets, setAssets] = useState<Asset[]>([]);
  const [assetPagination, setAssetPagination] = useState({
    page: 1,
    limit: 50,
    total: 0,
    pages: 0
  });
  const [assetFilters, setAssetFilters] = useState({
    asset_status: '',
    manufacturer: '',
    location: '',
    department: ''
  });
  
  // Asset sorting state
  const [assetSortConfig, setAssetSortConfig] = useState<{
    key: keyof Asset | null;
    direction: 'asc' | 'desc';
  }>({
    key: null,
    direction: 'asc'
  });
  
  // Capacity Planning State
  const [capacityData, setCapacityData] = useState<CapacityData[]>([]);
  
  // Dialog State
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [assetDetailDialogOpen, setAssetDetailDialogOpen] = useState(false);
  
  // Add Asset Modal State
  const [showAddAssetModal, setShowAddAssetModal] = useState(false);
  const [newAsset, setNewAsset] = useState({
    asset_tag: '',
    hostname: '',
    manufacturer: '',
    model: '',
    serial_number: '',
    location: '',
    department: '',
    owner: '',
    cost: 0,
    purchase_date: '',
    warranty_expiry: '',
    asset_status: 'active'
  });
  
  // Edit Asset Modal State
  const [showEditAssetModal, setShowEditAssetModal] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);
  
  // Delete Confirmation State
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [assetToDelete, setAssetToDelete] = useState<Asset | null>(null);

  const fetchAssets = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const params = {
        page: assetPagination.page,
        limit: assetPagination.limit,
        ...assetFilters
      };
      
      const response: AssetListResponse = await apiService.getAssets(params);
      setAssets(response.assets);
      setAssetPagination(response.pagination);
    } catch (err) {
      console.error('Error fetching assets:', err);
      setError('Failed to fetch assets. Please try again.');
      setNotification({
        message: 'Failed to fetch assets. Please try again.',
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchCapacityData = async () => {
    try {
      // This would typically fetch capacity data for multiple devices
      // For now, we'll simulate some data
      setCapacityData([
        {
          device_id: '1',
          hostname: 'server-01',
          capacity_data: [
            {
              metric_type: 'cpu',
              current_utilization: 75,
              peak_utilization: 85,
              average_utilization: 65,
              threshold_warning: 80,
              threshold_critical: 95,
              capacity_total: 100,
              capacity_available: 25,
              growth_rate: 5,
              projected_exhaustion: '2024-06-15T00:00:00Z',
              recommendations: 'Consider upgrading CPU or adding more cores',
              measured_at: new Date().toISOString()
            },
            {
              metric_type: 'memory',
              current_utilization: 60,
              peak_utilization: 75,
              average_utilization: 55,
              threshold_warning: 80,
              threshold_critical: 95,
              capacity_total: 64,
              capacity_available: 25.6,
              growth_rate: 3,
              projected_exhaustion: '2024-08-20T00:00:00Z',
              recommendations: 'Memory usage is healthy, monitor growth rate',
              measured_at: new Date().toISOString()
            }
          ]
        }
      ]);
    } catch (err) {
      console.error('Error fetching capacity data:', err);
    }
  };

  useEffect(() => {
    fetchAssets();
    fetchCapacityData();
  }, [assetPagination.page, assetFilters, fetchAssets]);

  const handleTabChange = (newValue: number) => {
    setTabValue(newValue);
  };

  const handleAssetFilterChange = (field: string, value: string) => {
    setAssetFilters(prev => ({ ...prev, [field]: value }));
    setAssetPagination(prev => ({ ...prev, page: 1 }));
  };

  const handleAssetPageChange = (page: number) => {
    setAssetPagination(prev => ({ ...prev, page }));
  };

  const handleViewAssetDetails = (asset: Asset) => {
    setSelectedAsset(asset);
    setAssetDetailDialogOpen(true);
  };

  const handleAssetHostnameClick = (asset: Asset) => {
    // Navigate to device details if this asset has a corresponding device
    if (asset.id) {
      navigate(`/device/${asset.id}`);
    }
  };

  const handleAssetSort = (key: keyof Asset) => {
    let direction: 'asc' | 'desc' = 'asc';
    if (assetSortConfig.key === key && assetSortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setAssetSortConfig({ key, direction });
  };

  const getAssetSortIcon = (columnKey: keyof Asset) => {
    if (assetSortConfig.key !== columnKey) {
      return (
        <svg className="w-4 h-4 ml-1 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
        </svg>
      );
    }
    
    if (assetSortConfig.direction === 'asc') {
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

  const sortedAssets = React.useMemo(() => {
    if (!assetSortConfig.key) return assets;
    
    return [...assets].sort((a, b) => {
      const aValue = a[assetSortConfig.key!];
      const bValue = b[assetSortConfig.key!];
      
      if (aValue === null || aValue === undefined) return 1;
      if (bValue === null || bValue === undefined) return -1;
      
      if (aValue < bValue) {
        return assetSortConfig.direction === 'asc' ? -1 : 1;
      }
      if (aValue > bValue) {
        return assetSortConfig.direction === 'asc' ? 1 : -1;
      }
      return 0;
    });
  }, [assets, assetSortConfig]);

  const handleRefresh = () => {
    fetchAssets();
    fetchCapacityData();
    setNotification({
      message: 'Inventory data refreshed successfully.',
      severity: 'success'
    });
  };

  const handleExportAssets = async () => {
    try {
      const exportData = await apiService.exportData({
        data_type: 'assets',
        format: 'csv',
        filters: assetFilters
      });
      
      // Create and download file
      const blob = new Blob([exportData.data], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = exportData.filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      setNotification({
        message: 'Asset data exported successfully.',
        severity: 'success'
      });
    } catch (err) {
      console.error('Error exporting asset data:', err);
      setNotification({
        message: 'Failed to export asset data. Please try again.',
        severity: 'error'
      });
    }
  };

  const getAssetStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'badge-success';
      case 'inactive':
        return 'badge-warning';
      case 'retired':
        return 'badge-error';
      case 'lost':
        return 'badge-error';
      case 'stolen':
        return 'badge-error';
      default:
        return 'badge-neutral';
    }
  };

  const getUtilizationColor = (utilization: number, warning: number, critical: number) => {
    if (utilization >= critical) return 'progress-error';
    if (utilization >= warning) return 'progress-warning';
    return 'progress-success';
  };

  // Add Asset Handlers
  const handleAddAsset = () => {
    setShowAddAssetModal(true);
  };

  const handleCreateAsset = async () => {
    try {
      await apiService.createAsset(newAsset);
      setShowAddAssetModal(false);
      setNewAsset({
        asset_tag: '',
        hostname: '',
        manufacturer: '',
        model: '',
        serial_number: '',
        location: '',
        department: '',
        owner: '',
        cost: 0,
        purchase_date: '',
        warranty_expiry: '',
        asset_status: 'active'
      });
      fetchAssets();
      setNotification({
        message: 'Asset created successfully.',
        severity: 'success'
      });
    } catch (err) {
      console.error('Error creating asset:', err);
      setNotification({
        message: 'Failed to create asset. Please try again.',
        severity: 'error'
      });
    }
  };

  // Edit Asset Handlers
  const handleEditAsset = (asset: Asset) => {
    setEditingAsset(asset);
    setShowEditAssetModal(true);
  };

  const handleUpdateAsset = async () => {
    if (!editingAsset) return;
    
    try {
      await apiService.updateAsset(editingAsset.id, editingAsset);
      setShowEditAssetModal(false);
      setEditingAsset(null);
      fetchAssets();
      setNotification({
        message: 'Asset updated successfully.',
        severity: 'success'
      });
    } catch (err) {
      console.error('Error updating asset:', err);
      setNotification({
        message: 'Failed to update asset. Please try again.',
        severity: 'error'
      });
    }
  };

  // Delete Asset Handlers
  const handleDeleteAsset = (asset: Asset) => {
    setAssetToDelete(asset);
    setShowDeleteConfirm(true);
  };

  const handleConfirmDeleteAsset = async () => {
    if (!assetToDelete) return;
    
    try {
      await apiService.deleteAsset(assetToDelete.id);
      setShowDeleteConfirm(false);
      setAssetToDelete(null);
      fetchAssets();
      setNotification({
        message: 'Asset deleted successfully.',
        severity: 'success'
      });
    } catch (err) {
      console.error('Error deleting asset:', err);
      setNotification({
        message: 'Failed to delete asset. Please try again.',
        severity: 'error'
      });
    }
  };

  const handleCancelDeleteAsset = () => {
    setShowDeleteConfirm(false);
    setAssetToDelete(null);
  };

  if (loading && assets.length === 0) {
    return (
      <div className="flex justify-center items-center min-h-96">
        <span className="loading loading-spinner loading-lg"></span>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="card bg-base-200 shadow-lg mb-6">
        <div className="card-body">
          <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
            <div>
              <h2 className="card-title text-2xl">Inventory Management</h2>
              <p className="text-base-content/70">
                Asset tracking, capacity planning, and utilization monitoring
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
              <button
                className="btn btn-outline"
                onClick={handleExportAssets}
                disabled={loading}
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Export
              </button>
              <button 
                className="btn btn-primary"
                onClick={handleAddAsset}
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                </svg>
                Add Asset
              </button>
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

      {/* Tabs */}
      <div className="card bg-base-100 shadow-lg">
        <div className="tabs tabs-boxed p-4">
          <button 
            className={`tab ${tabValue === 0 ? 'tab-active' : ''}`}
            onClick={() => handleTabChange(0)}
          >
            Asset Management
          </button>
          <button 
            className={`tab ${tabValue === 1 ? 'tab-active' : ''}`}
            onClick={() => handleTabChange(1)}
          >
            Capacity Planning
          </button>
          <button 
            className={`tab ${tabValue === 2 ? 'tab-active' : ''}`}
            onClick={() => handleTabChange(2)}
          >
            Utilization Metrics
          </button>
        </div>

        {/* Asset Management Tab */}
        {tabValue === 0 && (
          <div className="p-6">
            {/* Asset Filters */}
            <div className="card bg-base-200 mb-6">
              <div className="card-body">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="form-control">
                    <label className="label">
                      <span className="label-text">Asset Status</span>
                    </label>
                    <select 
                      className="select select-bordered w-full"
                      value={assetFilters.asset_status}
                      onChange={(e: React.ChangeEvent<HTMLSelectElement>) => handleAssetFilterChange('asset_status', e.target.value)}
                    >
                      <option value="">All Status</option>
                      <option value="active">Active</option>
                      <option value="inactive">Inactive</option>
                      <option value="retired">Retired</option>
                      <option value="lost">Lost</option>
                      <option value="stolen">Stolen</option>
                    </select>
                  </div>
                  <div className="form-control">
                    <label className="label">
                      <span className="label-text">Manufacturer</span>
                    </label>
                    <input
                      type="text"
                      className="input input-bordered"
                      placeholder="Cisco, HP, Dell..."
                      value={assetFilters.manufacturer}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleAssetFilterChange('manufacturer', e.target.value)}
                    />
                  </div>
                  <div className="form-control">
                    <label className="label">
                      <span className="label-text">Location</span>
                    </label>
                    <input
                      type="text"
                      className="input input-bordered"
                      placeholder="Data center, building..."
                      value={assetFilters.location}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleAssetFilterChange('location', e.target.value)}
                    />
                  </div>
                  <div className="form-control">
                    <label className="label">
                      <span className="label-text">Department</span>
                    </label>
                    <input
                      type="text"
                      className="input input-bordered"
                      placeholder="IT, Operations..."
                      value={assetFilters.department}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleAssetFilterChange('department', e.target.value)}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Asset Table */}
            <div className="overflow-x-auto">
              <table className="table table-zebra w-full">
                <thead>
                  <tr>
                    <th 
                      className="cursor-pointer hover:bg-base-200 select-none"
                      onClick={() => handleAssetSort('asset_tag')}
                    >
                      <div className="flex items-center">
                        Asset Tag
                        {getAssetSortIcon('asset_tag')}
                      </div>
                    </th>
                    <th 
                      className="cursor-pointer hover:bg-base-200 select-none"
                      onClick={() => handleAssetSort('hostname')}
                    >
                      <div className="flex items-center">
                        Hostname
                        {getAssetSortIcon('hostname')}
                      </div>
                    </th>
                    <th 
                      className="cursor-pointer hover:bg-base-200 select-none"
                      onClick={() => handleAssetSort('manufacturer')}
                    >
                      <div className="flex items-center">
                        Manufacturer
                        {getAssetSortIcon('manufacturer')}
                      </div>
                    </th>
                    <th 
                      className="cursor-pointer hover:bg-base-200 select-none"
                      onClick={() => handleAssetSort('model')}
                    >
                      <div className="flex items-center">
                        Model
                        {getAssetSortIcon('model')}
                      </div>
                    </th>
                    <th 
                      className="cursor-pointer hover:bg-base-200 select-none"
                      onClick={() => handleAssetSort('asset_status')}
                    >
                      <div className="flex items-center">
                        Status
                        {getAssetSortIcon('asset_status')}
                      </div>
                    </th>
                    <th 
                      className="cursor-pointer hover:bg-base-200 select-none"
                      onClick={() => handleAssetSort('location')}
                    >
                      <div className="flex items-center">
                        Location
                        {getAssetSortIcon('location')}
                      </div>
                    </th>
                    <th 
                      className="cursor-pointer hover:bg-base-200 select-none"
                      onClick={() => handleAssetSort('department')}
                    >
                      <div className="flex items-center">
                        Department
                        {getAssetSortIcon('department')}
                      </div>
                    </th>
                    <th 
                      className="cursor-pointer hover:bg-base-200 select-none"
                      onClick={() => handleAssetSort('cost')}
                    >
                      <div className="flex items-center">
                        Cost
                        {getAssetSortIcon('cost')}
                      </div>
                    </th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedAssets.map((asset) => (
                    <tr key={asset.id} className="hover">
                      <td>
                        <div>
                          <div className="font-bold">{asset.asset_tag || '-'}</div>
                          {asset.serial_number && (
                            <div className="text-sm opacity-50">S/N: {asset.serial_number}</div>
                          )}
                        </div>
                      </td>
                      <td>
                        <div 
                          className="font-bold text-primary cursor-pointer hover:underline"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleAssetHostnameClick(asset);
                          }}
                          title="Click to view device details and graphs"
                        >
                          {asset.hostname}
                        </div>
                      </td>
                      <td>{asset.manufacturer || '-'}</td>
                      <td>{asset.model || '-'}</td>
                      <td>
                        <span className={`badge ${getAssetStatusColor(asset.asset_status || '')}`}>
                          {asset.asset_status || 'unknown'}
                        </span>
                      </td>
                      <td>{asset.location || '-'}</td>
                      <td>{asset.department || '-'}</td>
                      <td>
                        {asset.cost ? `$${asset.cost.toLocaleString()}` : '-'}
                      </td>
                      <td>
                        <div className="flex gap-1">
                          <button
                            className="btn btn-sm btn-ghost"
                            onClick={() => handleViewAssetDetails(asset)}
                            title="View Details"
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                            </svg>
                          </button>
                          <button 
                            className="btn btn-sm btn-ghost" 
                            title="Edit Asset"
                            onClick={() => handleEditAsset(asset)}
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                            </svg>
                          </button>
                          <button 
                            className="btn btn-sm btn-ghost text-error" 
                            title="Delete Asset"
                            onClick={() => handleDeleteAsset(asset)}
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
            
            {/* Asset Pagination */}
            {assetPagination.pages > 1 && (
              <div className="flex justify-center mt-6">
                <div className="join">
                  {Array.from({ length: assetPagination.pages }, (_, i) => i + 1).map((page) => (
                    <button
                      key={page}
                      className={`join-item btn ${page === assetPagination.page ? 'btn-active' : ''}`}
                      onClick={() => handleAssetPageChange(page)}
                    >
                      {page}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Capacity Planning Tab */}
        {tabValue === 1 && (
          <div className="p-6">
            <div className="grid gap-6">
              {capacityData.map((device) => (
                <div key={device.device_id} className="card bg-base-100 shadow-lg">
                  <div className="card-body">
                    <h3 className="card-title">{device.hostname} - Capacity Planning</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {device.capacity_data.map((metric) => (
                        <div key={metric.metric_type} className="card bg-base-200">
                          <div className="card-body">
                            <div className="flex items-center mb-2">
                              <h4 className="card-title text-lg capitalize">{metric.metric_type} Utilization</h4>
                            </div>
                            
                            <div className="flex justify-between items-end mb-2">
                              <div className={`text-3xl font-bold ${
                                metric.current_utilization >= metric.threshold_critical ? 'text-error' :
                                metric.current_utilization >= metric.threshold_warning ? 'text-warning' :
                                'text-success'
                              }`}>
                                {metric.current_utilization}%
                              </div>
                              <div className="text-right text-sm opacity-70">
                                <div>Peak: {metric.peak_utilization}%</div>
                                <div>Avg: {metric.average_utilization}%</div>
                              </div>
                            </div>
                            
                            <progress 
                              className={`progress w-full ${getUtilizationColor(metric.current_utilization, metric.threshold_warning, metric.threshold_critical)}`}
                              value={metric.current_utilization} 
                              max="100"
                            ></progress>
                            
                            <div className="flex justify-between text-xs opacity-70 mb-2">
                              <span>Warning: {metric.threshold_warning}%</span>
                              <span>Critical: {metric.threshold_critical}%</span>
                            </div>
                            
                            {metric.capacity_total && (
                              <div className="text-sm opacity-70">
                                Total: {metric.capacity_total}GB | Available: {metric.capacity_available}GB
                              </div>
                            )}
                            
                            {metric.growth_rate && (
                              <div className="flex items-center mt-2">
                                <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                                </svg>
                                <span className="text-xs opacity-70">Growth: {metric.growth_rate}% per month</span>
                              </div>
                            )}
                            
                            {metric.projected_exhaustion && (
                              <div className="text-xs text-warning mt-2">
                                Projected exhaustion: {new Date(metric.projected_exhaustion).toLocaleDateString()}
                              </div>
                            )}
                            
                            {metric.recommendations && (
                              <div className="text-xs opacity-70 mt-2">
                                {metric.recommendations}
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Utilization Metrics Tab */}
        {tabValue === 2 && (
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="card bg-base-100 shadow-lg">
                <div className="card-body">
                  <h3 className="card-title">Overall Utilization Summary</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center">
                      <div className="text-4xl font-bold text-success">85%</div>
                      <div className="text-sm opacity-70">Devices Online</div>
                    </div>
                    <div className="text-center">
                      <div className="text-4xl font-bold text-warning">12%</div>
                      <div className="text-sm opacity-70">High Utilization</div>
                    </div>
                    <div className="text-center">
                      <div className="text-4xl font-bold text-info">3%</div>
                      <div className="text-sm opacity-70">Under Maintenance</div>
                    </div>
                    <div className="text-center">
                      <div className="text-4xl font-bold text-error">2%</div>
                      <div className="text-sm opacity-70">Critical Alerts</div>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="card bg-base-100 shadow-lg">
                <div className="card-body">
                  <h3 className="card-title">Resource Utilization Trends</h3>
                  <p className="text-sm opacity-70 mb-4">
                    Average utilization across all monitored devices
                  </p>
                  
                  <div className="space-y-4">
                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-sm">CPU</span>
                        <span className="text-sm">65%</span>
                      </div>
                      <progress className="progress progress-primary w-full" value="65" max="100"></progress>
                    </div>
                    
                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-sm">Memory</span>
                        <span className="text-sm">72%</span>
                      </div>
                      <progress className="progress progress-warning w-full" value="72" max="100"></progress>
                    </div>
                    
                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-sm">Storage</span>
                        <span className="text-sm">45%</span>
                      </div>
                      <progress className="progress progress-success w-full" value="45" max="100"></progress>
                    </div>
                    
                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-sm">Network</span>
                        <span className="text-sm">38%</span>
                      </div>
                      <progress className="progress progress-info w-full" value="38" max="100"></progress>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Asset Detail Dialog */}
      {assetDetailDialogOpen && (
        <div className="modal modal-open">
          <div className="modal-box max-w-2xl">
            <h3 className="font-bold text-lg mb-4">
              Asset Details - {selectedAsset?.asset_tag || selectedAsset?.hostname}
            </h3>
            {selectedAsset && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-semibold mb-2">Asset Information</h4>
                  <div className="space-y-1 text-sm">
                    <div><strong>Asset Tag:</strong> {selectedAsset.asset_tag || '-'}</div>
                    <div><strong>Hostname:</strong> {selectedAsset.hostname}</div>
                    <div><strong>Serial Number:</strong> {selectedAsset.serial_number || '-'}</div>
                    <div><strong>Manufacturer:</strong> {selectedAsset.manufacturer || '-'}</div>
                    <div><strong>Model:</strong> {selectedAsset.model || '-'}</div>
                    <div><strong>Status:</strong> {selectedAsset.asset_status || '-'}</div>
                  </div>
                </div>
                <div>
                  <h4 className="font-semibold mb-2">Location & Ownership</h4>
                  <div className="space-y-1 text-sm">
                    <div><strong>Location:</strong> {selectedAsset.location || '-'}</div>
                    <div><strong>Department:</strong> {selectedAsset.department || '-'}</div>
                    <div><strong>Owner:</strong> {selectedAsset.owner || '-'}</div>
                    <div><strong>Cost:</strong> {selectedAsset.cost ? `$${selectedAsset.cost.toLocaleString()}` : '-'}</div>
                    <div><strong>Purchase Date:</strong> {selectedAsset.purchase_date ? new Date(selectedAsset.purchase_date).toLocaleDateString() : '-'}</div>
                    <div><strong>Warranty Expiry:</strong> {selectedAsset.warranty_expiry ? new Date(selectedAsset.warranty_expiry).toLocaleDateString() : '-'}</div>
                  </div>
                </div>
              </div>
            )}
            <div className="modal-action">
              <button className="btn" onClick={() => setAssetDetailDialogOpen(false)}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Add Asset Modal */}
      {showAddAssetModal && (
        <div className="modal modal-open">
          <div className="modal-box max-w-2xl">
            <h3 className="font-bold text-lg mb-4">Add New Asset</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Asset Tag</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={newAsset.asset_tag}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, asset_tag: e.target.value }))}
                  placeholder="ASSET-001"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Hostname</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={newAsset.hostname}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, hostname: e.target.value }))}
                  placeholder="Asset Hostname"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Manufacturer</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={newAsset.manufacturer}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, manufacturer: e.target.value }))}
                  placeholder="Cisco, HP, Dell..."
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Model</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={newAsset.model}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, model: e.target.value }))}
                  placeholder="Model Number"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Serial Number</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={newAsset.serial_number}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, serial_number: e.target.value }))}
                  placeholder="Serial Number"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Location</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={newAsset.location}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, location: e.target.value }))}
                  placeholder="Data Center, Building..."
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Department</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={newAsset.department}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, department: e.target.value }))}
                  placeholder="IT, Engineering..."
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Owner</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={newAsset.owner}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, owner: e.target.value }))}
                  placeholder="Owner Name"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Cost</span>
                </label>
                <input
                  type="number"
                  className="input input-bordered"
                  value={newAsset.cost}
                  onChange={(e) => {
                    const value = parseFloat(e.target.value);
                    setNewAsset(prev => ({ ...prev, cost: isNaN(value) || value < 0 ? 0 : value }));
                  }}
                  placeholder="0.00"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Purchase Date</span>
                </label>
                <input
                  type="date"
                  className="input input-bordered"
                  value={newAsset.purchase_date}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, purchase_date: e.target.value }))}
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Warranty Expiry</span>
                </label>
                <input
                  type="date"
                  className="input input-bordered"
                  value={newAsset.warranty_expiry}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, warranty_expiry: e.target.value }))}
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Status</span>
                </label>
                <select
                  className="select select-bordered"
                  value={newAsset.asset_status}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, asset_status: e.target.value }))}
                >
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                  <option value="retired">Retired</option>
                  <option value="lost">Lost</option>
                  <option value="stolen">Stolen</option>
                </select>
              </div>
            </div>

            <div className="modal-action">
              <button className="btn" onClick={() => setShowAddAssetModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleCreateAsset}>Create Asset</button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Asset Modal */}
      {showEditAssetModal && editingAsset && (
        <div className="modal modal-open">
          <div className="modal-box max-w-2xl">
            <h3 className="font-bold text-lg mb-4">Edit Asset - {editingAsset.asset_tag || editingAsset.hostname}</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Asset Tag</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={editingAsset.asset_tag || ''}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, asset_tag: e.target.value } : null)}
                  placeholder="ASSET-001"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Hostname</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={editingAsset.hostname || ''}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, hostname: e.target.value } : null)}
                  placeholder="Asset Hostname"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Manufacturer</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={editingAsset.manufacturer || ''}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, manufacturer: e.target.value } : null)}
                  placeholder="Cisco, HP, Dell..."
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Model</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={editingAsset.model || ''}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, model: e.target.value } : null)}
                  placeholder="Model Number"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Serial Number</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={editingAsset.serial_number || ''}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, serial_number: e.target.value } : null)}
                  placeholder="Serial Number"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Location</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={editingAsset.location || ''}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, location: e.target.value } : null)}
                  placeholder="Data Center, Building..."
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Department</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={editingAsset.department || ''}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, department: e.target.value } : null)}
                  placeholder="IT, Engineering..."
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Owner</span>
                </label>
                <input
                  type="text"
                  className="input input-bordered"
                  value={editingAsset.owner || ''}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, owner: e.target.value } : null)}
                  placeholder="Owner Name"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Cost</span>
                </label>
                <input
                  type="number"
                  className="input input-bordered"
                  value={editingAsset.cost || 0}
                  onChange={(e) => {
                    const value = parseFloat(e.target.value);
                    setEditingAsset(prev => prev ? { ...prev, cost: isNaN(value) || value < 0 ? 0 : value } : null);
                  }}
                  placeholder="0.00"
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Purchase Date</span>
                </label>
                <input
                  type="date"
                  className="input input-bordered"
                  value={editingAsset.purchase_date || ''}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, purchase_date: e.target.value } : null)}
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Warranty Expiry</span>
                </label>
                <input
                  type="date"
                  className="input input-bordered"
                  value={editingAsset.warranty_expiry || ''}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, warranty_expiry: e.target.value } : null)}
                />
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Status</span>
                </label>
                <select
                  className="select select-bordered"
                  value={editingAsset.asset_status || 'active'}
                  onChange={(e) => setEditingAsset(prev => prev ? { ...prev, asset_status: e.target.value } : null)}
                >
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                  <option value="retired">Retired</option>
                  <option value="lost">Lost</option>
                  <option value="stolen">Stolen</option>
                </select>
              </div>
            </div>

            <div className="modal-action">
              <button className="btn" onClick={() => setShowEditAssetModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleUpdateAsset}>Update Asset</button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && assetToDelete && (
        <div className="modal modal-open">
          <div className="modal-box">
            <h3 className="font-bold text-lg mb-4">Confirm Delete</h3>
            <p className="mb-4">
              Are you sure you want to delete the asset "{assetToDelete.asset_tag || assetToDelete.hostname}"? 
              This action cannot be undone.
            </p>
            <div className="modal-action">
              <button className="btn" onClick={handleCancelDeleteAsset}>Cancel</button>
              <button className="btn btn-error" onClick={handleConfirmDeleteAsset}>Delete Asset</button>
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

export default InventoryTab;
