import React, { useState, useEffect } from 'react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, ScatterChart, Scatter,
  ComposedChart, ReferenceLine, Legend
} from 'recharts';
import RealTimeChart from './RealTimeChart';

interface MetricData {
  timestamp: string;
  value: number;
  unit?: string;
  device_id?: number;
  device_name?: string;
}

interface AlertData {
  id: number;
  severity: string;
  message: string;
  created_at: string;
  device_id: number;
  device_name: string;
}

interface DeviceData {
  id: number;
  hostname: string;
  ip_address: string;
  current_state: string;
  device_type: string;
  last_poll_time: string;
}

interface AdvancedDashboardProps {
  devices: DeviceData[];
  metrics: MetricData[];
  alerts: AlertData[];
  timeRange: number;
  selectedDevices: number[];
  onDeviceSelect: (deviceIds: number[]) => void;
}

const AdvancedDashboard: React.FC<AdvancedDashboardProps> = ({
  devices,
  metrics,
  alerts,
  timeRange,
  selectedDevices,
  onDeviceSelect
}) => {
  const [selectedMetric, setSelectedMetric] = useState<string>('cpu');
  const [chartType, setChartType] = useState<'line' | 'area' | 'bar' | 'scatter'>('area');
  const [showThresholds, setShowThresholds] = useState(true);
  const [groupByDevice, setGroupByDevice] = useState(false);

  // Filter metrics based on selected devices and metric type
  const filteredMetrics = metrics.filter(metric => 
    selectedDevices.length === 0 || selectedDevices.includes(metric.device_id || 0)
  ).filter(metric => 
    metric.unit?.toLowerCase().includes(selectedMetric) || 
    metric.device_name?.toLowerCase().includes(selectedMetric)
  );

  // Group metrics by device if enabled
  const processedMetrics = groupByDevice 
    ? filteredMetrics.reduce((acc, metric) => {
        const deviceName = metric.device_name || `Device ${metric.device_id}`;
        if (!acc[deviceName]) {
          acc[deviceName] = [];
        }
        acc[deviceName].push(metric);
        return acc;
      }, {} as Record<string, MetricData[]>)
    : { 'All Devices': filteredMetrics };

  // Calculate statistics
  const calculateStats = (data: MetricData[]) => {
    if (data.length === 0) return { min: 0, max: 0, avg: 0, current: 0 };
    
    const values = data.map(d => d.value);
    return {
      min: Math.min(...values),
      max: Math.max(...values),
      avg: values.reduce((sum, val) => sum + val, 0) / values.length,
      current: data[data.length - 1]?.value || 0
    };
  };

  // Get device status distribution
  const deviceStatusData = devices.reduce((acc, device) => {
    acc[device.current_state] = (acc[device.current_state] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const statusColors = {
    'online': '#10b981',
    'offline': '#ef4444',
    'maintenance': '#f59e0b',
    'decommissioned': '#6b7280'
  };

  // Get alert severity distribution
  const alertSeverityData = alerts.reduce((acc, alert) => {
    acc[alert.severity] = (acc[alert.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const severityColors = {
    'critical': '#ef4444',
    'high': '#f59e0b',
    'medium': '#3b82f6',
    'low': '#10b981'
  };

  const renderChart = (data: MetricData[], title: string) => {
    const chartProps = {
      data: data,
      height: 300
    };

    switch (chartType) {
      case 'line':
        return (
          <LineChart {...chartProps}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis 
              dataKey="timestamp" 
              tickFormatter={(value) => new Date(value).toLocaleTimeString()}
            />
            <YAxis />
            <Tooltip 
              labelFormatter={(value) => new Date(value).toLocaleString()}
              formatter={(value: number) => [value.toFixed(2), title]}
            />
            <Line 
              type="monotone" 
              dataKey="value" 
              stroke="#3b82f6" 
              strokeWidth={2}
              dot={{ fill: '#3b82f6', strokeWidth: 2, r: 4 }}
            />
            {showThresholds && (
              <>
                <ReferenceLine y={80} stroke="#f59e0b" strokeDasharray="5 5" />
                <ReferenceLine y={95} stroke="#ef4444" strokeDasharray="5 5" />
              </>
            )}
          </LineChart>
        );

      case 'area':
        return (
          <AreaChart {...chartProps}>
            <defs>
              <linearGradient id="gradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis 
              dataKey="timestamp" 
              tickFormatter={(value) => new Date(value).toLocaleTimeString()}
            />
            <YAxis />
            <Tooltip 
              labelFormatter={(value) => new Date(value).toLocaleString()}
              formatter={(value: number) => [value.toFixed(2), title]}
            />
            <Area 
              type="monotone" 
              dataKey="value" 
              stroke="#3b82f6" 
              fill="url(#gradient)"
              strokeWidth={2}
            />
            {showThresholds && (
              <>
                <ReferenceLine y={80} stroke="#f59e0b" strokeDasharray="5 5" />
                <ReferenceLine y={95} stroke="#ef4444" strokeDasharray="5 5" />
              </>
            )}
          </AreaChart>
        );

      case 'bar':
        return (
          <BarChart {...chartProps}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis 
              dataKey="timestamp" 
              tickFormatter={(value) => new Date(value).toLocaleTimeString()}
            />
            <YAxis />
            <Tooltip 
              labelFormatter={(value) => new Date(value).toLocaleString()}
              formatter={(value: number) => [value.toFixed(2), title]}
            />
            <Bar dataKey="value" fill="#3b82f6" />
          </BarChart>
        );

      case 'scatter':
        return (
          <ScatterChart {...chartProps}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis 
              dataKey="timestamp" 
              tickFormatter={(value) => new Date(value).toLocaleTimeString()}
            />
            <YAxis />
            <Tooltip 
              labelFormatter={(value) => new Date(value).toLocaleString()}
              formatter={(value: number) => [value.toFixed(2), title]}
            />
            <Scatter dataKey="value" fill="#3b82f6" />
          </ScatterChart>
        );

      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Controls */}
      <div className="bg-base-100 rounded-lg shadow-lg p-4">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
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
            </select>
          </div>

          <div className="form-control">
            <label className="label">
              <span className="label-text">Chart Type</span>
            </label>
            <select
              className="select select-bordered"
              value={chartType}
              onChange={(e) => setChartType(e.target.value as any)}
            >
              <option value="line">Line Chart</option>
              <option value="area">Area Chart</option>
              <option value="bar">Bar Chart</option>
              <option value="scatter">Scatter Plot</option>
            </select>
          </div>

          <div className="form-control">
            <label className="label cursor-pointer">
              <span className="label-text">Show Thresholds</span>
              <input
                type="checkbox"
                className="toggle toggle-primary"
                checked={showThresholds}
                onChange={(e) => setShowThresholds(e.target.checked)}
              />
            </label>
          </div>

          <div className="form-control">
            <label className="label cursor-pointer">
              <span className="label-text">Group by Device</span>
              <input
                type="checkbox"
                className="toggle toggle-primary"
                checked={groupByDevice}
                onChange={(e) => setGroupByDevice(e.target.checked)}
              />
            </label>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {Object.entries(processedMetrics).map(([deviceName, data]) => {
          const stats = calculateStats(data);
          return (
            <div key={deviceName} className="stat bg-base-100 rounded-lg shadow-lg">
              <div className="stat-title">{deviceName}</div>
              <div className="stat-value text-primary">{stats.current.toFixed(1)}</div>
              <div className="stat-desc">
                Min: {stats.min.toFixed(1)} | Max: {stats.max.toFixed(1)} | Avg: {stats.avg.toFixed(1)}
              </div>
            </div>
          );
        })}
      </div>

      {/* Main Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Performance Chart */}
        <div className="bg-base-100 rounded-lg shadow-lg p-4">
          <h3 className="text-lg font-semibold mb-4">Performance Metrics</h3>
          <ResponsiveContainer width="100%" height={400}>
            {renderChart(filteredMetrics, selectedMetric)}
          </ResponsiveContainer>
        </div>

        {/* Real-time Chart */}
        <div className="bg-base-100 rounded-lg shadow-lg p-4">
          <RealTimeChart
            data={filteredMetrics.slice(-50)} // Last 50 data points
            title={`Real-time ${selectedMetric.toUpperCase()}`}
            metricType={selectedMetric}
            unit="%"
            threshold={{ warning: 80, critical: 95 }}
            height={400}
            showArea={true}
            showThresholds={showThresholds}
            updateInterval={5000}
            maxDataPoints={50}
          />
        </div>
      </div>

      {/* Distribution Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Device Status Distribution */}
        <div className="bg-base-100 rounded-lg shadow-lg p-4">
          <h3 className="text-lg font-semibold mb-4">Device Status Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={Object.entries(deviceStatusData).map(([status, count]) => ({
                  name: status,
                  value: count,
                  color: statusColors[status as keyof typeof statusColors] || '#6b7280'
                }))}
                cx="50%"
                cy="50%"
                outerRadius={80}
                dataKey="value"
                label={({ name, value }) => `${name}: ${value}`}
              >
                {Object.entries(deviceStatusData).map(([status, count], index) => (
                  <Cell 
                    key={`cell-${index}`} 
                    fill={statusColors[status as keyof typeof statusColors] || '#6b7280'} 
                  />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Alert Severity Distribution */}
        <div className="bg-base-100 rounded-lg shadow-lg p-4">
          <h3 className="text-lg font-semibold mb-4">Alert Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={Object.entries(alertSeverityData).map(([severity, count]) => ({
              severity,
              count,
              color: severityColors[severity as keyof typeof severityColors] || '#6b7280'
            }))}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="severity" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="count" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Multi-Device Comparison */}
      {groupByDevice && Object.keys(processedMetrics).length > 1 && (
        <div className="bg-base-100 rounded-lg shadow-lg p-4">
          <h3 className="text-lg font-semibold mb-4">Multi-Device Comparison</h3>
          <ResponsiveContainer width="100%" height={400}>
            <ComposedChart data={filteredMetrics}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="timestamp" 
                tickFormatter={(value) => new Date(value).toLocaleTimeString()}
              />
              <YAxis />
              <Tooltip 
                labelFormatter={(value) => new Date(value).toLocaleString()}
                formatter={(value: number, name: string) => [value.toFixed(2), name]}
              />
              <Legend />
              {Object.keys(processedMetrics).map((deviceName, index) => (
                <Line
                  key={deviceName}
                  type="monotone"
                  dataKey="value"
                  stroke={`hsl(${index * 60}, 70%, 50%)`}
                  strokeWidth={2}
                  name={deviceName}
                  connectNulls={false}
                />
              ))}
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};

export default AdvancedDashboard;
