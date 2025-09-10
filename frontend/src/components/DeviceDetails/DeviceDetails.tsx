import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { apiService, Device, DeviceMetrics, HardwareComponent, SoftwareComponent, NetworkInterfaceDetails } from '../../services/api';

const DeviceDetails: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [device, setDevice] = useState<Device | null>(null);
  const [metrics, setMetrics] = useState<DeviceMetrics[]>([]);
  const [hardwareComponents, setHardwareComponents] = useState<HardwareComponent[]>([]);
  const [softwareComponents, setSoftwareComponents] = useState<SoftwareComponent[]>([]);
  const [networkInterfaces, setNetworkInterfaces] = useState<NetworkInterfaceDetails[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string>('overview');

  const fetchDeviceData = async () => {
    if (!id) return;
    
    try {
      setLoading(true);
      setError(null);

      // Fetch device details
      const deviceResponse = await apiService.getDevice(id);
      setDevice(deviceResponse);

      // Fetch metrics with error handling
      try {
        const metricsResponse = await apiService.getDeviceMetrics(id);
        setMetrics(metricsResponse.metrics || []);
      } catch (metricsError) {
        console.warn('Could not fetch metrics:', metricsError);
        setMetrics([]);
      }

      // Fetch hardware components with error handling
      try {
        const hardwareResponse = await apiService.getHardwareComponents(id);
        setHardwareComponents(hardwareResponse.components || []);
      } catch (hardwareError) {
        console.warn('Could not fetch hardware components:', hardwareError);
        setHardwareComponents([]);
      }

      // Fetch software components with error handling
      try {
        const softwareResponse = await apiService.getSoftwareComponents(id);
        setSoftwareComponents(softwareResponse.components || []);
      } catch (softwareError) {
        console.warn('Could not fetch software components:', softwareError);
        setSoftwareComponents([]);
      }

      // Fetch network interfaces with error handling
      try {
        const interfacesResponse = await apiService.getNetworkInterfaces(id);
        setNetworkInterfaces(interfacesResponse.interfaces || []);
      } catch (interfacesError) {
        console.warn('Could not fetch network interfaces:', interfacesError);
        setNetworkInterfaces([]);
      }

    } catch (err: any) {
      console.error('Error fetching device data:', err);
      setError(err.message || 'Failed to fetch device data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDeviceData();
    
    // Set up polling for real-time updates
    const interval = setInterval(() => {
      fetchDeviceData();
    }, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, [id, fetchDeviceData]);

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'online': return 'text-success';
      case 'offline': return 'text-error';
      case 'maintenance': return 'text-warning';
      default: return 'text-base-content';
    }
  };

  const formatMetricsData = (metrics: DeviceMetrics[]) => {
    return metrics.slice(-20).map((metric, index) => ({
      time: new Date(metric.timestamp).toLocaleTimeString(),
      cpu: metric.cpu_usage || 0,
      memory: metric.memory_usage || 0,
      network: metric.network_usage || 0
    }));
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-screen">
        <div className="loading loading-spinner loading-lg"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="alert alert-error">
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span>{error}</span>
        <button className="btn btn-outline btn-sm" onClick={fetchDeviceData}>
          Retry
        </button>
      </div>
    );
  }

  if (!device) {
    return (
      <div className="alert alert-warning">
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
        <span>Device not found</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="flex items-center gap-4">
        <button
          className="btn btn-outline"
          onClick={() => window.history.back()}
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Back
        </button>
        <div>
          <h1 className="text-3xl font-bold">{device.name || device.hostname}</h1>
          <p className="text-base-content/60">{device.ip_address}</p>
        </div>
        <div className="ml-auto">
          <div className={`badge badge-lg ${getStatusColor(device.status)}`}>
            {device.status}
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="tabs tabs-bordered">
        {['overview', 'hardware', 'software', 'interfaces'].map((tab) => (
          <button 
            key={tab}
            className={`tab tab-bordered ${activeTab === tab ? 'tab-active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {/* Overview Tab Content */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Device Info Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="card bg-base-100 shadow-xl">
              <div className="card-body">
                <h2 className="card-title">Device Info</h2>
                <div className="space-y-2">
                  <p><strong>Type:</strong> {device.device_type}</p>
                  <p><strong>OS:</strong> {device.os_name} {device.os_version}</p>
                  <p><strong>Location:</strong> {device.location || 'Not specified'}</p>
                  <p><strong>Last Seen:</strong> {device.last_seen ? new Date(device.last_seen).toLocaleString() : 'Never'}</p>
                </div>
              </div>
            </div>

            <div className="card bg-base-100 shadow-xl">
              <div className="card-body">
                <h2 className="card-title">Performance</h2>
                <div className="space-y-2">
                  <p><strong>Uptime:</strong> {device.uptime || 'Unknown'}</p>
                  <p><strong>Response Time:</strong> {device.response_time ? `${device.response_time}ms` : 'N/A'}</p>
                  <p><strong>SNMP Status:</strong> {device.snmp_status || 'Unknown'}</p>
                </div>
              </div>
            </div>

            <div className="card bg-base-100 shadow-xl">
              <div className="card-body">
                <h2 className="card-title">Components</h2>
                <div className="space-y-2">
                  <p><strong>Hardware:</strong> {hardwareComponents.length} components</p>
                  <p><strong>Software:</strong> {softwareComponents.length} components</p>
                  <p><strong>Interfaces:</strong> {networkInterfaces.length} interfaces</p>
                </div>
              </div>
            </div>
          </div>

          {/* Metrics Chart */}
          <div className="card bg-base-100 shadow-xl">
            <div className="card-body">
              <h2 className="card-title">Performance Metrics</h2>
              {metrics.length > 0 ? (
                <div className="h-80">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={formatMetricsData(metrics)}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="time" />
                      <YAxis />
                      <Tooltip />
                      <Line type="monotone" dataKey="cpu" stroke="#8884d8" name="CPU %" />
                      <Line type="monotone" dataKey="memory" stroke="#82ca9d" name="Memory %" />
                      <Line type="monotone" dataKey="network" stroke="#ffc658" name="Network %" />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-base-content/60">No metrics data available</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Hardware Tab Content */}
      {activeTab === 'hardware' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-bold">Hardware Components</h2>
            <div className="text-sm text-gray-500">
              {hardwareComponents.length} components found
            </div>
          </div>

          {hardwareComponents.length > 0 ? (
            <div className="grid gap-4">
              {hardwareComponents.map((component) => (
                <div key={component.id} className="card bg-base-100 shadow">
                  <div className="card-body">
                    <div className="flex justify-between items-start">
                      <div>
                        <h3 className="card-title">{component.name}</h3>
                        <p className="text-base-content/60">{component.component_type}</p>
                        {component.description && (
                          <p className="text-sm mt-2">{component.description}</p>
                        )}
                      </div>
                      <div className="text-right">
                        <div className={`badge ${component.status === 'operational' ? 'badge-success' : 'badge-error'}`}>
                          {component.status}
                        </div>
                        {component.manufacturer && (
                          <p className="text-xs text-base-content/60 mt-1">{component.manufacturer}</p>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="card bg-base-100 shadow">
              <div className="card-body text-center">
                <p className="text-base-content/60">No hardware components found</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Software Tab Content */}
      {activeTab === 'software' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-bold">Software Components</h2>
            <div className="text-sm text-gray-500">
              {softwareComponents.length} components found
            </div>
          </div>

          {softwareComponents.length > 0 ? (
            <div className="grid gap-4">
              {softwareComponents.map((component) => (
                <div key={component.id} className="card bg-base-100 shadow">
                  <div className="card-body">
                    <div className="flex justify-between items-start">
                      <div>
                        <h3 className="card-title">{component.software_name}</h3>
                        <p className="text-base-content/60">Version: {component.version || 'Unknown'}</p>
                        {component.vendor && (
                          <p className="text-sm text-base-content/60">Vendor: {component.vendor}</p>
                        )}
                      </div>
                      <div className="text-right">
                        <div className={`badge ${component.status === 'active' ? 'badge-success' : 'badge-warning'}`}>
                          {component.status}
                        </div>
                        {component.license_expiry && (
                          <p className="text-xs text-base-content/60 mt-1">
                            License expires: {new Date(component.license_expiry).toLocaleDateString()}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="card bg-base-100 shadow">
              <div className="card-body text-center">
                <p className="text-base-content/60">No software components found</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Interfaces Tab Content */}
      {activeTab === 'interfaces' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-bold">Network Interfaces</h2>
            <div className="text-sm text-gray-500">
              {networkInterfaces.length} interfaces found
            </div>
          </div>

          {networkInterfaces.length > 0 ? (
            <div className="grid gap-4">
              {networkInterfaces.map((networkInterface) => (
                <div key={networkInterface.id} className="card bg-base-100 shadow">
                  <div className="card-body">
                    <div className="flex justify-between items-start">
                      <div>
                        <h3 className="card-title">{networkInterface.interface_name}</h3>
                        <p className="text-base-content/60">{networkInterface.interface_type}</p>
                        {networkInterface.mac_address && (
                          <p className="text-sm text-base-content/60">MAC: {networkInterface.mac_address}</p>
                        )}
                        {networkInterface.ip_address && (
                          <p className="text-sm text-base-content/60">IP: {networkInterface.ip_address}</p>
                        )}
                      </div>
                      <div className="text-right">
                        <div className={`badge ${networkInterface.status === 'up' ? 'badge-success' : 'badge-error'}`}>
                          {networkInterface.status}
                        </div>
                        {networkInterface.speed && (
                          <p className="text-xs text-base-content/60 mt-1">Speed: {networkInterface.speed}</p>
                        )}
                      </div>
                    </div>
                    {networkInterface.description && (
                      <p className="text-sm mt-2">{networkInterface.description}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="card bg-base-100 shadow">
              <div className="card-body text-center">
                <p className="text-base-content/60">No network interfaces found</p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default DeviceDetails;