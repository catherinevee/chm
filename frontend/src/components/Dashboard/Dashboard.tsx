import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts';
import { apiService, Device, Alert as AlertType } from '../../services/api';

interface DashboardStats {
  totalDevices: number;
  healthyDevices: number;
  degradedDevices: number;
  criticalDevices: number;
  unreachableDevices: number;
  activeAlerts: number;
}

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [devices, setDevices] = useState<Device[]>([]);
  const [alerts, setAlerts] = useState<AlertType[]>([]);
  const [stats, setStats] = useState<DashboardStats>({
    totalDevices: 0,
    healthyDevices: 0,
    degradedDevices: 0,
    criticalDevices: 0,
    unreachableDevices: 0,
    activeAlerts: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [devicesData, alertsData] = await Promise.all([
        apiService.getDevices(),
        apiService.getAlerts(),
      ]);

      setDevices(devicesData.devices);
      setAlerts(alertsData);

      // Calculate stats using actual device states
      const stats: DashboardStats = {
        totalDevices: devicesData.devices.length,
        healthyDevices: devicesData.devices.filter(d => d.current_state === 'online').length,
        degradedDevices: devicesData.devices.filter(d => d.current_state === 'maintenance').length,
        criticalDevices: devicesData.devices.filter(d => d.current_state === 'decommissioned').length,
        unreachableDevices: devicesData.devices.filter(d => d.current_state === 'offline').length,
        activeAlerts: alertsData.filter(a => !a.resolved).length,
      };

      setStats(stats);
      setError(null);
    } catch (err) {
      setError('Failed to fetch dashboard data');
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // Refresh data every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const getStateColor = (state: string) => {
    switch (state) {
      case 'online':
        return 'success';
      case 'maintenance':
        return 'warning';
      case 'decommissioned':
        return 'error';
      case 'offline':
        return 'neutral';
      default:
        return 'neutral';
    }
  };

  const getStateIcon = (state: string) => {
    switch (state) {
      case 'online':
        return 'OK';
      case 'maintenance':
        return 'WARN';
      case 'decommissioned':
        return 'DECOMM';
      case 'offline':
        return 'OFFLINE';
      default:
        return 'UNKNOWN';
    }
  };

  const handleRefresh = () => {
    fetchData();
  };

  const handleDeviceClick = (deviceId: string) => {
    navigate(`/device/${deviceId}`);
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-96">
        <span className="loading loading-spinner loading-lg"></span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h1 className="text-4xl font-bold">Catalyst Health Monitor Dashboard</h1>
        <button 
          className="btn btn-primary"
          onClick={handleRefresh}
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh
        </button>
      </div>

      {error && (
        <div className="alert alert-error">
          <svg className="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>{error}</span>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
        <div className="stat bg-base-200 rounded-lg">
          <div className="stat-title">Total Devices</div>
          <div className="stat-value text-primary">{stats.totalDevices}</div>
        </div>
        <div className="stat bg-base-200 rounded-lg">
          <div className="stat-title">Healthy</div>
          <div className="stat-value text-success">{stats.healthyDevices}</div>
        </div>
        <div className="stat bg-base-200 rounded-lg">
          <div className="stat-title">Degraded</div>
          <div className="stat-value text-warning">{stats.degradedDevices}</div>
        </div>
        <div className="stat bg-base-200 rounded-lg">
          <div className="stat-title">Critical</div>
          <div className="stat-value text-error">{stats.criticalDevices}</div>
        </div>
        <div className="stat bg-base-200 rounded-lg">
          <div className="stat-title">Unreachable</div>
          <div className="stat-value text-neutral">{stats.unreachableDevices}</div>
        </div>
        <div className="stat bg-base-200 rounded-lg">
          <div className="stat-title">Active Alerts</div>
          <div className="stat-value text-error">{stats.activeAlerts}</div>
        </div>
      </div>

      {/* Devices List */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <div className="bg-base-100 shadow-xl rounded-lg p-6">
            <h2 className="text-2xl font-bold mb-4">Device Status</h2>
            {devices.length === 0 ? (
              <p className="text-base-content/60">No devices found</p>
            ) : (
              <div className="space-y-4">
                {devices.map((device) => (
                  <div key={device.id} className="bg-base-200 rounded-lg p-4">
                    <div className="flex justify-between items-center">
                      <div>
                        <h3 className="font-bold text-lg">{device.hostname}</h3>
                        <p className="text-base-content/60">
                          {device.ip_address} • {device.device_type}
                        </p>
                        {device.last_poll_time && (
                          <p className="text-sm text-base-content/60">
                            Last poll: {new Date(device.last_poll_time).toLocaleString()}
                          </p>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <div className={`badge badge-${getStateColor(device.current_state)} gap-2`}>
                          {getStateIcon(device.current_state)}
                          {device.current_state}
                        </div>
                        {device.consecutive_failures > 0 && (
                          <div className="badge badge-warning">
                            {device.consecutive_failures} failures
                          </div>
                        )}
                        <button
                          className="btn btn-sm btn-outline"
                          onClick={() => handleDeviceClick(device.id)}
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                          </svg>
                          View Details
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="lg:col-span-1">
          <div className="bg-base-100 shadow-xl rounded-lg p-6">
            <h2 className="text-2xl font-bold mb-4">Recent Alerts</h2>
            {alerts.length === 0 ? (
              <p className="text-base-content/60">No alerts</p>
            ) : (
              <div className="space-y-4">
                {alerts.slice(0, 5).map((alert) => (
                  <div key={alert.id} className="bg-base-200 rounded-lg p-4">
                    <h3 className="font-bold text-sm">{alert.message}</h3>
                    <p className="text-xs text-base-content/60">
                      {new Date(alert.created_at).toLocaleString()}
                    </p>
                    <div className="mt-2">
                      <div className={`badge badge-${alert.severity === 'critical' ? 'error' : 'warning'}`}>
                        {alert.severity}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
