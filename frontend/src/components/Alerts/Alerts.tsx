import React, { useState, useEffect } from 'react';
import { apiService, Alert as AlertType } from '../../services/api';

const Alerts: React.FC = () => {
  const [alerts, setAlerts] = useState<AlertType[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const alertsData = await apiService.getAlerts();
      setAlerts(alertsData);
      setError(null);
    } catch (err) {
      setError('Failed to fetch alerts');
      console.error('Alerts fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    // Refresh alerts every 30 seconds
    const interval = setInterval(fetchAlerts, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleAcknowledge = async (alertId: string) => {
    try {
      await apiService.acknowledgeAlert(alertId);
      // Refresh alerts after acknowledging
      fetchAlerts();
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'error';
      case 'warning':
        return 'warning';
      case 'info':
        return 'info';
      default:
        return 'neutral';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'CRIT';
      case 'warning':
        return 'WARN';
      case 'info':
        return 'INFO';
      default:
        return 'INFO';
    }
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
        <h1 className="text-4xl font-bold">Alerts Management</h1>
        <button
          className="btn btn-primary"
          onClick={fetchAlerts}
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

      {/* Alerts Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="stat bg-base-200 rounded-lg">
          <div className="stat-title">Total Alerts</div>
          <div className="stat-value text-primary">{alerts.length}</div>
        </div>
        <div className="stat bg-base-200 rounded-lg">
          <div className="stat-title">Critical</div>
          <div className="stat-value text-error">{alerts.filter(a => a.severity === 'critical').length}</div>
        </div>
        <div className="stat bg-base-200 rounded-lg">
          <div className="stat-title">Warning</div>
          <div className="stat-value text-warning">{alerts.filter(a => a.severity === 'warning').length}</div>
        </div>
        <div className="stat bg-base-200 rounded-lg">
          <div className="stat-title">Unacknowledged</div>
          <div className="stat-value text-info">{alerts.filter(a => !a.acknowledged).length}</div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-base-100 shadow-xl rounded-lg p-6">
        <h2 className="text-2xl font-bold mb-4">All Alerts</h2>
        {alerts.length === 0 ? (
          <p className="text-base-content/60">No alerts found</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="table table-zebra">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Device</th>
                  <th>Metric</th>
                  <th>Value</th>
                  <th>Message</th>
                  <th>Created</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <div className={`badge badge-${getSeverityColor(alert.severity)} gap-2`}>
                        {getSeverityIcon(alert.severity)}
                        {alert.severity}
                      </div>
                    </td>
                    <td>{alert.device_id}</td>
                    <td>{alert.metric_name}</td>
                    <td>{alert.metric_value}</td>
                    <td className="max-w-xs truncate">{alert.message}</td>
                    <td>{new Date(alert.created_at).toLocaleString()}</td>
                    <td>
                      <div className="flex gap-1">
                        {alert.acknowledged && (
                          <div className="badge badge-success">Acknowledged</div>
                        )}
                        {alert.resolved && (
                          <div className="badge badge-info">Resolved</div>
                        )}
                      </div>
                    </td>
                    <td>
                      {!alert.acknowledged && (
                        <button
                          className="btn btn-sm btn-outline"
                          onClick={() => handleAcknowledge(alert.id)}
                        >
                          Acknowledge
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default Alerts;
