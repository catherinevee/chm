import React, { useState, useEffect } from 'react';
import apiService, { 
  DevicePerformanceMetrics, 
  PerformanceGraphData, 
  PerformanceSummary,
  Device 
} from '../services/api';

const PerformanceGraphsComponent: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string>('');
  const [selectedMetric, setSelectedMetric] = useState<string>('cpu');
  const [timeRange, setTimeRange] = useState<number>(24);
  const [performanceData, setPerformanceData] = useState<DevicePerformanceMetrics | null>(null);
  const [graphData, setGraphData] = useState<PerformanceGraphData | null>(null);
  const [summary, setSummary] = useState<PerformanceSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadDevices();
    loadSummary();
  }, []);

  useEffect(() => {
    if (selectedDevice) {
      loadPerformanceData();
      loadGraphData();
    }
  }, [selectedDevice, selectedMetric, timeRange]);

  const loadDevices = async () => {
    try {
      const response = await apiService.getDevices();
      setDevices(response.devices);
    } catch (err) {
      console.error('Failed to load devices:', err);
    }
  };

  const loadSummary = async () => {
    try {
      const data = await apiService.getPerformanceSummary();
      setSummary(data);
    } catch (err) {
      console.error('Failed to load performance summary:', err);
    }
  };

  const loadPerformanceData = async () => {
    if (!selectedDevice) return;
    
    try {
      setLoading(true);
      setError(null);
      const data = await apiService.getDevicePerformanceMetrics(
        selectedDevice,
        selectedMetric,
        timeRange
      );
      setPerformanceData(data);
    } catch (err) {
      setError('Failed to load performance data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadGraphData = async () => {
    if (!selectedDevice) return;
    
    try {
      const data = await apiService.getPerformanceGraphData(
        selectedDevice,
        selectedMetric,
        timeRange,
        5 // 5-minute intervals
      );
      setGraphData(data);
    } catch (err) {
      console.error('Failed to load graph data:', err);
    }
  };

  const getMetricColor = (metricType: string) => {
    switch (metricType) {
      case 'cpu': return 'text-blue-600';
      case 'memory': return 'text-green-600';
      case 'disk': return 'text-purple-600';
      case 'network': return 'text-orange-600';
      case 'temperature': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  const getMetricIcon = (metricType: string) => {
    switch (metricType) {
      case 'cpu': return '';
      case 'memory': return '';
      case 'disk': return '';
      case 'network': return '';
      case 'temperature': return '';
      case 'uptime': return '';
      case 'interface': return '';
      case 'bandwidth': return '';
      case 'latency': return '';
      case 'packet_loss': return '';
      default: return '';
    }
  };

  const formatValue = (value: number, unit?: string) => {
    if (unit === '%') return `${value.toFixed(1)}%`;
    if (unit === 'MB') return `${(value / 1024 / 1024).toFixed(2)} MB`;
    if (unit === 'Mbps') return `${value.toFixed(2)} Mbps`;
    if (unit === 'ms') return `${value.toFixed(2)} ms`;
    if (unit === 'C') return `${value.toFixed(1)}C`;
    return value.toFixed(2);
  };

  const renderSimpleGraph = (data: PerformanceGraphData) => {
    if (!data.data_points || data.data_points.length === 0) {
      return <p className="text-center text-gray-500">No data available</p>;
    }

    const maxValue = Math.max(...data.data_points.map(d => d.value));
    const minValue = Math.min(...data.data_points.map(d => d.value));

    return (
      <div className="space-y-2">
        {data.data_points.map((point, index) => {
          const percentage = maxValue > minValue 
            ? ((point.value - minValue) / (maxValue - minValue)) * 100 
            : 50;
          
          return (
            <div key={index} className="flex items-center gap-2">
              <div className="text-xs w-16 text-right">
                {new Date(point.timestamp).toLocaleTimeString()}
              </div>
              <div className="flex-1 bg-gray-200 rounded-full h-4">
                <div 
                  className="bg-blue-500 h-4 rounded-full transition-all duration-300"
                  style={{ width: `${percentage}%` }}
                ></div>
              </div>
              <div className="text-xs w-16 text-left">
                {formatValue(point.value, point.unit)}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className="container mx-auto p-4">
      <h2 className="text-2xl font-bold mb-6">Performance Graphs</h2>

      {/* Performance Summary */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="stat bg-base-100 shadow rounded-lg">
            <div className="stat-title">Total Devices</div>
            <div className="stat-value text-primary">{summary.total_devices}</div>
          </div>
          
          <div className="stat bg-base-100 shadow rounded-lg">
            <div className="stat-title">Total Metrics</div>
            <div className="stat-value text-info">{summary.total_metrics}</div>
          </div>
          
          <div className="stat bg-base-100 shadow rounded-lg">
            <div className="stat-title">Normal Status</div>
            <div className="stat-value text-success">
              {summary.summary.filter(s => s.status === 'normal').length}
            </div>
          </div>
          
          <div className="stat bg-base-100 shadow rounded-lg">
            <div className="stat-title">Critical Status</div>
            <div className="stat-value text-error">
              {summary.summary.filter(s => s.status === 'critical').length}
            </div>
          </div>
        </div>
      )}

      {/* Device and Metric Selection */}
      <div className="card bg-base-100 shadow-xl mb-6">
        <div className="card-body">
          <h3 className="card-title">Select Device and Metric</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="form-control">
              <label className="label">
                <span className="label-text">Device</span>
              </label>
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

            <div className="form-control">
              <label className="label">
                <span className="label-text">Metric Type</span>
              </label>
              <select
                className="select select-bordered"
                value={selectedMetric}
                onChange={(e) => setSelectedMetric(e.target.value)}
              >
                <option value="cpu">CPU Usage</option>
                <option value="memory">Memory Usage</option>
                <option value="disk">Disk Usage</option>
                <option value="network">Network Traffic</option>
                <option value="temperature">Temperature</option>
                <option value="uptime">Uptime</option>
                <option value="interface">Interface Status</option>
                <option value="bandwidth">Bandwidth</option>
                <option value="latency">Latency</option>
                <option value="packet_loss">Packet Loss</option>
              </select>
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Time Range</span>
              </label>
              <select
                className="select select-bordered"
                value={timeRange}
                onChange={(e) => setTimeRange(Number(e.target.value))}
              >
                <option value={1}>Last Hour</option>
                <option value={6}>Last 6 Hours</option>
                <option value={24}>Last 24 Hours</option>
                <option value={168}>Last Week</option>
                <option value={720}>Last Month</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="alert alert-error mb-4">
          <span>{error}</span>
        </div>
      )}

      {/* Performance Data */}
      {selectedDevice && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Current Metrics */}
          <div className="card bg-base-100 shadow-xl">
            <div className="card-body">
              <h3 className="card-title">
                {getMetricIcon(selectedMetric)} Current Metrics
              </h3>
              
              {loading ? (
                <div className="flex justify-center">
                  <span className="loading loading-spinner loading-lg"></span>
                </div>
              ) : performanceData && performanceData.metrics.length > 0 ? (
                <div className="space-y-4">
                  {performanceData.metrics.slice(0, 10).map((metric) => (
                    <div key={metric.id} className="bg-base-200 p-4 rounded-lg">
                      <div className="flex justify-between items-center mb-2">
                        <h4 className="font-semibold">{metric.metric_name}</h4>
                        <span className={`badge ${metric.threshold_critical && metric.metric_value > metric.threshold_critical ? 'badge-error' : 'badge-success'}`}>
                          {formatValue(metric.metric_value, metric.metric_unit)}
                        </span>
                      </div>
                      
                      <div className="text-sm text-gray-600">
                        <p>Type: {metric.metric_type}</p>
                        {metric.interface_name && <p>Interface: {metric.interface_name}</p>}
                        <p>Time: {new Date(metric.timestamp).toLocaleString()}</p>
                        
                        {metric.threshold_warning && (
                          <p>Warning: {formatValue(metric.threshold_warning, metric.metric_unit)}</p>
                        )}
                        {metric.threshold_critical && (
                          <p>Critical: {formatValue(metric.threshold_critical, metric.metric_unit)}</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-center text-gray-500">No metrics available</p>
              )}
            </div>
          </div>

          {/* Performance Graph */}
          <div className="card bg-base-100 shadow-xl">
            <div className="card-body">
              <h3 className="card-title">
                {getMetricIcon(selectedMetric)} Performance Graph
              </h3>
              
              {graphData ? (
                <div>
                  <div className="mb-4">
                    <h4 className="font-semibold mb-2">
                      {graphData.device_hostname} - {selectedMetric.toUpperCase()}
                    </h4>
                    <p className="text-sm text-gray-600">
                      Last {timeRange} hours ({graphData.data_points.length} data points)
                    </p>
                  </div>
                  
                  {renderSimpleGraph(graphData)}
                </div>
              ) : (
                <p className="text-center text-gray-500">No graph data available</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Performance Summary Table */}
      {summary && (
        <div className="card bg-base-100 shadow-xl mt-6">
          <div className="card-body">
            <h3 className="card-title">Performance Summary</h3>
            <div className="overflow-x-auto">
              <table className="table table-zebra">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Metric</th>
                    <th>Current Value</th>
                    <th>Status</th>
                    <th>Last Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {summary.summary.map((item, index) => (
                    <tr key={index}>
                      <td>
                        <div className="flex items-center gap-2">
                          <span>{getMetricIcon(item.metric_type)}</span>
                          <span>{item.device_hostname}</span>
                        </div>
                      </td>
                      <td>
                        <span className={getMetricColor(item.metric_type)}>
                          {item.metric_name}
                        </span>
                      </td>
                      <td>
                        <span className="font-semibold">
                          {formatValue(item.current_value, item.unit)}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${item.status === 'normal' ? 'badge-success' : 'badge-error'}`}>
                          {item.status}
                        </span>
                      </td>
                      <td>{new Date(item.timestamp).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PerformanceGraphsComponent;
