import React, { useState, useEffect } from 'react';
import { apiService, NetworkTopology as NetworkTopologyType } from '../services/api';

interface NetworkTopologyProps {
  className?: string;
}

const NetworkTopology: React.FC<NetworkTopologyProps> = ({ className = '' }) => {
  const [topology, setTopology] = useState<NetworkTopologyType | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadTopology = async (forceRefresh: boolean = false) => {
    try {
      setLoading(true);
      setError(null);
      const data = await apiService.getNetworkTopology();
      setTopology(data);
    } catch (err: any) {
      console.error('Error loading network topology:', err);
      setError(err.message || 'Failed to load network topology');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTopology();
  }, []);

  const handleRefresh = () => {
    loadTopology(true);
  };

  if (loading) {
    return (
      <div className={`flex justify-center items-center min-h-64 ${className}`}>
        <div className="loading loading-spinner loading-lg"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`alert alert-error ${className}`}>
        <div className="flex-1">
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>{error}</span>
          <button className="btn btn-sm" onClick={handleRefresh}>Retry</button>
        </div>
      </div>
    );
  }

  if (!topology) {
    return (
      <div className={`alert alert-info ${className}`}>
        <span>No topology data available</span>
      </div>
    );
  }

  return (
    <div className={`space-y-6 ${className}`}>
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Network Topology</h2>
        <button className="btn btn-primary" onClick={handleRefresh}>
          <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Devices */}
        <div className="card bg-base-100 shadow-xl">
          <div className="card-body">
            <h3 className="card-title">Devices ({topology.devices.length})</h3>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {topology.devices.map((device) => (
                <div key={device.id} className="flex justify-between items-center p-2 bg-base-200 rounded">
                  <div>
                    <div className="font-medium">{device.hostname}</div>
                    <div className="text-sm text-base-content/60">{device.ip_address}</div>
                  </div>
                  <div className="text-right">
                    <div className={`badge ${device.status === 'online' ? 'badge-success' : 'badge-error'}`}>
                      {device.status}
                    </div>
                    <div className="text-xs text-base-content/60">{device.device_type}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Relationships */}
        <div className="card bg-base-100 shadow-xl">
          <div className="card-body">
            <h3 className="card-title">Relationships ({topology.relationships.length})</h3>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {topology.relationships.map((relationship) => (
                <div key={relationship.id} className="p-2 bg-base-200 rounded">
                  <div className="font-medium">{relationship.relationship_type}</div>
                  <div className="text-sm text-base-content/60">
                    {relationship.parent_device_id} → {relationship.child_device_id}
                  </div>
                  {relationship.bandwidth && (
                    <div className="text-xs text-base-content/60">
                      Bandwidth: {relationship.bandwidth} Mbps
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Topology Visualization Placeholder */}
      <div className="card bg-base-100 shadow-xl">
        <div className="card-body">
          <h3 className="card-title">Network Diagram</h3>
          <div className="flex justify-center items-center h-64 bg-base-200 rounded">
            <div className="text-center text-base-content/60">
              <svg className="w-16 h-16 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
              <p>Network diagram visualization coming soon</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkTopology;
