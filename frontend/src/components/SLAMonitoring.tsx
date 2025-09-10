import React, { useState, useEffect } from 'react';
import apiService, { SLAMetric, Device } from '../services/api';

const SLAMonitoringComponent: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string>('');
  const [slaMetrics, setSlaMetrics] = useState<SLAMetric[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newSLA, setNewSLA] = useState({
    sla_name: '',
    sla_type: 'uptime',
    target_value: 99.9,
    measurement_period: 60
  });

  useEffect(() => {
    loadDevices();
  }, []);

  const loadDevices = async () => {
    try {
      const response = await apiService.getDevices();
      setDevices(response.devices);
    } catch (err) {
      console.error('Failed to load devices:', err);
    }
  };

  const loadSLAMetrics = async () => {
    if (!selectedDevice) return;
    
    try {
      setLoading(true);
      setError(null);
      const data = await apiService.getDeviceSLAMetrics(selectedDevice);
      setSlaMetrics(data.sla_metrics);
    } catch (err) {
      setError('Failed to load SLA metrics');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedDevice) {
      loadSLAMetrics();
    }
  }, [selectedDevice, loadSLAMetrics]);

  const createSLAMetric = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedDevice) return;
    
    // Validate SLA data
    if (!newSLA.sla_name.trim()) {
      setError('SLA name is required');
      return;
    }
    
    if (newSLA.target_value <= 0 || newSLA.target_value > 100) {
      setError('Target value must be between 0 and 100');
      return;
    }
    
    if (newSLA.measurement_period <= 0) {
      setError('Measurement period must be greater than 0');
      return;
    }
    
    try {
      setLoading(true);
      setError(null);
      
      await apiService.createSLAMetric({
        device_id: selectedDevice,
        ...newSLA,
        sla_name: newSLA.sla_name.trim()
      });
      
      // Reset form
      setNewSLA({
        sla_name: '',
        sla_type: 'uptime',
        target_value: 99.9,
        measurement_period: 60
      });
      setShowCreateForm(false);
      
      // Reload metrics
      await loadSLAMetrics();
      
      alert('SLA metric created successfully!');
    } catch (err) {
      setError('Failed to create SLA metric');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const updateSLAMetric = async (slaId: string, updates: any) => {
    try {
      await apiService.updateSLAMetric(slaId, updates);
      await loadSLAMetrics(); // Reload to get updated data
    } catch (err) {
      setError('Failed to update SLA metric');
      console.error(err);
    }
  };

  const getSLAStatusColor = (status?: string) => {
    switch (status) {
      case 'met': return 'text-success';
      case 'breached': return 'text-error';
      case 'warning': return 'text-warning';
      default: return 'text-info';
    }
  };

  const getSLAStatusBadge = (status?: string) => {
    switch (status) {
      case 'met': return 'badge-success';
      case 'breached': return 'badge-error';
      case 'warning': return 'badge-warning';
      default: return 'badge-info';
    }
  };

  const getSLATypeIcon = (slaType: string) => {
    switch (slaType) {
      case 'uptime': return '';
      case 'response_time': return '';
      case 'availability': return 'PASS:';
      default: return '';
    }
  };

  const formatUptime = (percentage?: number) => {
    if (!percentage) return 'N/A';
    return `${percentage.toFixed(2)}%`;
  };

  const formatDowntime = (minutes?: number) => {
    if (!minutes) return 'N/A';
    if (minutes < 60) return `${minutes} minutes`;
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    return `${hours}h ${remainingMinutes}m`;
  };

  return (
    <div className="container mx-auto p-4">
      <h2 className="text-2xl font-bold mb-6">SLA Monitoring</h2>

      {/* Device Selection */}
      <div className="card bg-base-100 shadow-xl mb-6">
        <div className="card-body">
          <h3 className="card-title">Select Device</h3>
          <div className="form-control">
            <select
              className="select select-bordered"
              value={selectedDevice}
              onChange={(e) => setSelectedDevice(e.target.value)}
            >
              <option value="">Select a device</option>
              {devices.map((device) => (
                <option key={device.id} value={device.id}>
                  {device.hostname} ({device.ip_address})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="alert alert-error mb-4">
          <span>{error}</span>
        </div>
      )}

      {/* SLA Metrics for Selected Device */}
      {selectedDevice && (
        <div className="space-y-6">
          {/* Header with Create Button */}
          <div className="flex justify-between items-center">
            <h3 className="text-xl font-semibold">
              SLA Metrics for {devices.find(d => d.id === selectedDevice)?.hostname}
            </h3>
            <button
              className="btn btn-primary"
              onClick={() => setShowCreateForm(true)}
            >
              Create SLA Metric
            </button>
          </div>

          {/* Create SLA Form */}
          {showCreateForm && (
            <div className="card bg-base-100 shadow-xl">
              <div className="card-body">
                <h4 className="card-title">Create New SLA Metric</h4>
                <form onSubmit={createSLAMetric} className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="form-control">
                      <label className="label">
                        <span className="label-text">SLA Name</span>
                      </label>
                      <input
                        type="text"
                        placeholder="e.g., Core Switch Uptime"
                        className="input input-bordered"
                        value={newSLA.sla_name}
                        onChange={(e) => setNewSLA({...newSLA, sla_name: e.target.value})}
                        required
                      />
                    </div>

                    <div className="form-control">
                      <label className="label">
                        <span className="label-text">SLA Type</span>
                      </label>
                      <select
                        className="select select-bordered"
                        value={newSLA.sla_type}
                        onChange={(e) => setNewSLA({...newSLA, sla_type: e.target.value})}
                      >
                        <option value="uptime">Uptime</option>
                        <option value="response_time">Response Time</option>
                        <option value="availability">Availability</option>
                      </select>
                    </div>

                    <div className="form-control">
                      <label className="label">
                        <span className="label-text">Target Value</span>
                      </label>
                      <input
                        type="number"
                        step="0.1"
                        placeholder="99.9"
                        className="input input-bordered"
                        value={newSLA.target_value}
                        onChange={(e) => {
                          const value = parseFloat(e.target.value);
                          if (!isNaN(value) && value >= 0 && value <= 100) {
                            setNewSLA({...newSLA, target_value: value});
                          }
                        }}
                        required
                      />
                    </div>

                    <div className="form-control">
                      <label className="label">
                        <span className="label-text">Measurement Period (minutes)</span>
                      </label>
                      <input
                        type="number"
                        placeholder="60"
                        className="input input-bordered"
                        value={newSLA.measurement_period}
                        onChange={(e) => {
                          const value = parseInt(e.target.value);
                          if (!isNaN(value) && value > 0) {
                            setNewSLA({...newSLA, measurement_period: value});
                          }
                        }}
                        required
                      />
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={loading}
                    >
                      {loading ? 'Creating...' : 'Create SLA'}
                    </button>
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => setShowCreateForm(false)}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}

          {/* SLA Metrics Display */}
          {loading ? (
            <div className="flex justify-center">
              <span className="loading loading-spinner loading-lg"></span>
            </div>
          ) : slaMetrics.length === 0 ? (
            <div className="card bg-base-100 shadow-xl">
              <div className="card-body">
                <p className="text-center text-gray-500">No SLA metrics found for this device</p>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {slaMetrics.map((sla) => (
                <div key={sla.id} className="card bg-base-100 shadow-xl">
                  <div className="card-body">
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <h4 className="card-title">
                          {getSLATypeIcon(sla.sla_type)} {sla.sla_name}
                        </h4>
                        <p className="text-sm text-gray-600">{sla.sla_type}</p>
                      </div>
                      <span className={`badge ${getSLAStatusBadge(sla.sla_status)}`}>
                        {sla.sla_status || 'Unknown'}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-4 mb-4">
                      <div className="stat bg-base-200 rounded-lg p-3">
                        <div className="stat-title text-xs">Target</div>
                        <div className="stat-value text-lg">{sla.target_value}%</div>
                      </div>
                      
                      <div className="stat bg-base-200 rounded-lg p-3">
                        <div className="stat-title text-xs">Current</div>
                        <div className={`stat-value text-lg ${getSLAStatusColor(sla.sla_status)}`}>
                          {sla.current_value ? `${sla.current_value}%` : 'N/A'}
                        </div>
                      </div>
                    </div>

                    <div className="space-y-2 mb-4">
                      <div className="flex justify-between text-sm">
                        <span>Uptime:</span>
                        <span className="font-semibold">{formatUptime(sla.uptime_percentage)}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span>Downtime:</span>
                        <span className="font-semibold">{formatDowntime(sla.downtime_minutes)}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span>Total Outages:</span>
                        <span className="font-semibold">{sla.total_outages}</span>
                      </div>
                      {sla.last_measurement && (
                        <div className="flex justify-between text-sm">
                          <span>Last Updated:</span>
                          <span>{new Date(sla.last_measurement).toLocaleString()}</span>
                        </div>
                      )}
                    </div>

                    {/* Quick Update Buttons */}
                    <div className="flex gap-2">
                      <button
                        className="btn btn-sm btn-outline"
                        onClick={() => updateSLAMetric(sla.id, { sla_status: 'met' })}
                      >
                        Mark Met
                      </button>
                      <button
                        className="btn btn-sm btn-outline btn-warning"
                        onClick={() => updateSLAMetric(sla.id, { sla_status: 'warning' })}
                      >
                        Mark Warning
                      </button>
                      <button
                        className="btn btn-sm btn-outline btn-error"
                        onClick={() => updateSLAMetric(sla.id, { sla_status: 'breached' })}
                      >
                        Mark Breached
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* SLA Summary for All Devices */}
      {!selectedDevice && (
        <div className="card bg-base-100 shadow-xl">
          <div className="card-body">
            <h3 className="card-title">SLA Overview</h3>
            <p className="text-gray-600 mb-4">
              Select a device above to view and manage its SLA metrics. SLA monitoring helps ensure 
              your network devices meet performance and availability targets.
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="stat bg-base-200 rounded-lg">
                <div className="stat-title">Uptime SLA</div>
                <div className="stat-value text-success">99.9%</div>
                <div className="stat-desc">Target uptime for critical devices</div>
              </div>
              
              <div className="stat bg-base-200 rounded-lg">
                <div className="stat-title">Response Time</div>
                <div className="stat-value text-info">&lt; 100ms</div>
                <div className="stat-desc">Target response time for network devices</div>
              </div>
              
              <div className="stat bg-base-200 rounded-lg">
                <div className="stat-title">Availability</div>
                <div className="stat-value text-primary">99.95%</div>
                <div className="stat-desc">Overall network availability target</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SLAMonitoringComponent;
