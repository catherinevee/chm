/**
 * CHM Real-Time Dashboard Component
 * Advanced visualization with real-time updates and interactive features
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ScatterChart,
  Scatter,
  ComposedChart
} from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Slider } from '@/components/ui/slider';
import { 
  Play, 
  Pause, 
  RefreshCw, 
  Settings, 
  Download, 
  Maximize2,
  Minimize2,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Activity,
  Zap
} from 'lucide-react';

interface MetricData {
  timestamp: string;
  value: number;
  device_id: number;
  device_name: string;
  metric_name: string;
  unit: string;
}

interface AlertData {
  id: number;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'active' | 'resolved' | 'acknowledged';
  device_name: string;
  created_at: string;
  message: string;
}

interface DeviceStatus {
  id: number;
  hostname: string;
  ip_address: string;
  status: 'online' | 'offline' | 'degraded';
  cpu_usage: number;
  memory_usage: number;
  last_seen: string;
}

interface DashboardConfig {
  refreshInterval: number;
  autoRefresh: boolean;
  chartType: 'line' | 'area' | 'bar' | 'composed';
  timeRange: '1h' | '6h' | '24h' | '7d' | '30d';
  showGrid: boolean;
  showLegend: boolean;
  showTooltip: boolean;
  animation: boolean;
}

const RealTimeDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<MetricData[]>([]);
  const [alerts, setAlerts] = useState<AlertData[]>([]);
  const [devices, setDevices] = useState<DeviceStatus[]>([]);
  const [config, setConfig] = useState<DashboardConfig>({
    refreshInterval: 5000,
    autoRefresh: true,
    chartType: 'line',
    timeRange: '1h',
    showGrid: true,
    showLegend: true,
    showTooltip: true,
    animation: true
  });
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [selectedDevices, setSelectedDevices] = useState<number[]>([]);
  const [selectedMetrics, setSelectedMetrics] = useState<string[]>(['cpu_usage', 'memory_usage']);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // WebSocket connection for real-time updates
  useEffect(() => {
    const connectWebSocket = () => {
      try {
        const ws = new WebSocket('ws://localhost:8000/ws/dashboard');
        
        ws.onopen = () => {
          console.log('WebSocket connected');
          setError(null);
        };
        
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            handleWebSocketMessage(data);
          } catch (err) {
            console.error('Error parsing WebSocket message:', err);
          }
        };
        
        ws.onclose = () => {
          console.log('WebSocket disconnected');
          // Reconnect after 5 seconds
          setTimeout(connectWebSocket, 5000);
        };
        
        ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          setError('WebSocket connection error');
        };
        
        wsRef.current = ws;
      } catch (err) {
        console.error('Failed to connect WebSocket:', err);
        setError('Failed to connect to real-time updates');
      }
    };

    if (config.autoRefresh) {
      connectWebSocket();
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [config.autoRefresh]);

  // Polling fallback for data updates
  useEffect(() => {
    if (config.autoRefresh && !wsRef.current) {
      intervalRef.current = setInterval(fetchData, config.refreshInterval);
    } else if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [config.autoRefresh, config.refreshInterval]);

  const handleWebSocketMessage = useCallback((data: any) => {
    switch (data.type) {
      case 'metrics':
        setMetrics(prev => [...prev, ...data.data].slice(-1000)); // Keep last 1000 points
        break;
      case 'alerts':
        setAlerts(data.data);
        break;
      case 'devices':
        setDevices(data.data);
        break;
      default:
        console.log('Unknown WebSocket message type:', data.type);
    }
  }, []);

  const fetchData = useCallback(async () => {
    if (isLoading) return;
    
    setIsLoading(true);
    try {
      const [metricsRes, alertsRes, devicesRes] = await Promise.all([
        fetch(`/api/v1/metrics/realtime?time_range=${config.timeRange}&devices=${selectedDevices.join(',')}`),
        fetch('/api/v1/alerts/recent'),
        fetch('/api/v1/devices/status')
      ]);

      if (metricsRes.ok) {
        const metricsData = await metricsRes.json();
        setMetrics(metricsData);
      }

      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        setAlerts(alertsData);
      }

      if (devicesRes.ok) {
        const devicesData = await devicesRes.json();
        setDevices(devicesData);
      }

      setError(null);
    } catch (err) {
      console.error('Error fetching data:', err);
      setError('Failed to fetch data');
    } finally {
      setIsLoading(false);
    }
  }, [config.timeRange, selectedDevices, isLoading]);

  // Initial data fetch
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleConfigChange = (key: keyof DashboardConfig, value: any) => {
    setConfig(prev => ({ ...prev, [key]: value }));
  };

  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
  };

  const exportData = () => {
    const data = {
      metrics,
      alerts,
      devices,
      timestamp: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `chm-dashboard-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      case 'low': return '#22c55e';
      default: return '#6b7280';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return '#22c55e';
      case 'degraded': return '#eab308';
      case 'offline': return '#ef4444';
      default: return '#6b7280';
    }
  };

  // Process metrics data for charts
  const processMetricsData = () => {
    const groupedData: { [key: string]: any } = {};
    
    metrics.forEach(metric => {
      const key = metric.timestamp;
      if (!groupedData[key]) {
        groupedData[key] = { timestamp: metric.timestamp };
      }
      groupedData[key][`${metric.device_name}_${metric.metric_name}`] = metric.value;
    });
    
    return Object.values(groupedData).sort((a, b) => 
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
  };

  const chartData = processMetricsData();

  return (
    <div className={`p-6 ${isFullscreen ? 'fixed inset-0 z-50 bg-background' : ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold">Real-Time Dashboard</h1>
          <p className="text-muted-foreground">Live monitoring and analytics</p>
        </div>
        
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchData}
            disabled={isLoading}
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
          
          <Button
            variant="outline"
            size="sm"
            onClick={exportData}
          >
            <Download className="h-4 w-4" />
          </Button>
          
          <Button
            variant="outline"
            size="sm"
            onClick={toggleFullscreen}
          >
            {isFullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
          </Button>
        </div>
      </div>

      {/* Controls */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Dashboard Controls
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Auto Refresh</label>
              <div className="flex items-center space-x-2">
                <Switch
                  checked={config.autoRefresh}
                  onCheckedChange={(checked) => handleConfigChange('autoRefresh', checked)}
                />
                <span className="text-sm">{config.autoRefresh ? 'On' : 'Off'}</span>
              </div>
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Refresh Interval</label>
              <Slider
                value={[config.refreshInterval / 1000]}
                onValueChange={([value]) => handleConfigChange('refreshInterval', value * 1000)}
                min={1}
                max={60}
                step={1}
                className="w-full"
              />
              <span className="text-xs text-muted-foreground">{config.refreshInterval / 1000}s</span>
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Time Range</label>
              <Select
                value={config.timeRange}
                onValueChange={(value) => handleConfigChange('timeRange', value)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1h">1 Hour</SelectItem>
                  <SelectItem value="6h">6 Hours</SelectItem>
                  <SelectItem value="24h">24 Hours</SelectItem>
                  <SelectItem value="7d">7 Days</SelectItem>
                  <SelectItem value="30d">30 Days</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Chart Type</label>
              <Select
                value={config.chartType}
                onValueChange={(value) => handleConfigChange('chartType', value)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="line">Line Chart</SelectItem>
                  <SelectItem value="area">Area Chart</SelectItem>
                  <SelectItem value="bar">Bar Chart</SelectItem>
                  <SelectItem value="composed">Composed Chart</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Error Display */}
      {error && (
        <Card className="mb-6 border-red-200 bg-red-50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-red-600">
              <AlertTriangle className="h-5 w-5" />
              <span>{error}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Main Content */}
      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="devices">Devices</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {/* Key Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Total Devices</p>
                    <p className="text-2xl font-bold">{devices.length}</p>
                  </div>
                  <Activity className="h-8 w-8 text-blue-500" />
                </div>
                <div className="flex items-center mt-2">
                  <Badge variant="secondary">
                    {devices.filter(d => d.status === 'online').length} Online
                  </Badge>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Active Alerts</p>
                    <p className="text-2xl font-bold">{alerts.filter(a => a.status === 'active').length}</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-red-500" />
                </div>
                <div className="flex items-center mt-2">
                  <Badge variant="destructive">
                    {alerts.filter(a => a.severity === 'critical').length} Critical
                  </Badge>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Avg CPU Usage</p>
                    <p className="text-2xl font-bold">
                      {devices.length > 0 
                        ? Math.round(devices.reduce((sum, d) => sum + d.cpu_usage, 0) / devices.length)
                        : 0}%
                    </p>
                  </div>
                  <TrendingUp className="h-8 w-8 text-green-500" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Avg Memory Usage</p>
                    <p className="text-2xl font-bold">
                      {devices.length > 0 
                        ? Math.round(devices.reduce((sum, d) => sum + d.memory_usage, 0) / devices.length)
                        : 0}%
                    </p>
                  </div>
                  <TrendingDown className="h-8 w-8 text-orange-500" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Real-time Chart */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5" />
                Real-Time Metrics
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-96">
                <ResponsiveContainer width="100%" height="100%">
                  {config.chartType === 'line' && (
                    <LineChart data={chartData}>
                      {config.showGrid && <CartesianGrid strokeDasharray="3 3" />}
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      {config.showTooltip && <Tooltip />}
                      {config.showLegend && <Legend />}
                      {selectedMetrics.map((metric, index) => (
                        <Line
                          key={metric}
                          type="monotone"
                          dataKey={metric}
                          stroke={`hsl(${index * 60}, 70%, 50%)`}
                          strokeWidth={2}
                          dot={false}
                          animationDuration={config.animation ? 300 : 0}
                        />
                      ))}
                    </LineChart>
                  )}
                  
                  {config.chartType === 'area' && (
                    <AreaChart data={chartData}>
                      {config.showGrid && <CartesianGrid strokeDasharray="3 3" />}
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      {config.showTooltip && <Tooltip />}
                      {config.showLegend && <Legend />}
                      {selectedMetrics.map((metric, index) => (
                        <Area
                          key={metric}
                          type="monotone"
                          dataKey={metric}
                          stackId="1"
                          stroke={`hsl(${index * 60}, 70%, 50%)`}
                          fill={`hsl(${index * 60}, 70%, 50%)`}
                          fillOpacity={0.6}
                          animationDuration={config.animation ? 300 : 0}
                        />
                      ))}
                    </AreaChart>
                  )}
                  
                  {config.chartType === 'bar' && (
                    <BarChart data={chartData}>
                      {config.showGrid && <CartesianGrid strokeDasharray="3 3" />}
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      {config.showTooltip && <Tooltip />}
                      {config.showLegend && <Legend />}
                      {selectedMetrics.map((metric, index) => (
                        <Bar
                          key={metric}
                          dataKey={metric}
                          fill={`hsl(${index * 60}, 70%, 50%)`}
                          animationDuration={config.animation ? 300 : 0}
                        />
                      ))}
                    </BarChart>
                  )}
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="metrics" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Metrics Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-96">
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="timestamp" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    {selectedMetrics.map((metric, index) => (
                      <Line
                        key={metric}
                        type="monotone"
                        dataKey={metric}
                        stroke={`hsl(${index * 60}, 70%, 50%)`}
                        strokeWidth={2}
                        dot={false}
                      />
                    ))}
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="alerts" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Recent Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {alerts.map((alert) => (
                  <div
                    key={alert.id}
                    className="flex items-center justify-between p-4 border rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: getSeverityColor(alert.severity) }}
                      />
                      <div>
                        <p className="font-medium">{alert.title}</p>
                        <p className="text-sm text-muted-foreground">{alert.message}</p>
                        <p className="text-xs text-muted-foreground">
                          {alert.device_name} • {new Date(alert.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <Badge variant={alert.severity === 'critical' ? 'destructive' : 'secondary'}>
                      {alert.severity}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="devices" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Device Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {devices.map((device) => (
                  <div
                    key={device.id}
                    className="flex items-center justify-between p-4 border rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: getStatusColor(device.status) }}
                      />
                      <div>
                        <p className="font-medium">{device.hostname}</p>
                        <p className="text-sm text-muted-foreground">{device.ip_address}</p>
                        <p className="text-xs text-muted-foreground">
                          Last seen: {new Date(device.last_seen).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <p className="text-sm font-medium">CPU: {device.cpu_usage}%</p>
                        <p className="text-sm font-medium">Memory: {device.memory_usage}%</p>
                      </div>
                      <Badge variant={device.status === 'online' ? 'default' : 'destructive'}>
                        {device.status}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default RealTimeDashboard;
