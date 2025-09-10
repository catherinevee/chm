import React, { useState, useEffect } from 'react';
import apiService, { NetworkDiscovery } from '../services/api';

const NetworkDiscoveryComponent: React.FC = () => {
  const [discoveries, setDiscoveries] = useState<NetworkDiscovery[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newDiscovery, setNewDiscovery] = useState({
    network_cidr: '',
    discovery_protocol: 'snmp'
  });

  useEffect(() => {
    loadDiscoveries();
  }, []);

  const loadDiscoveries = async () => {
    try {
      setLoading(true);
      const response = await apiService.listDiscoveries();
      setDiscoveries(response.discoveries);
    } catch (err) {
      setError('Failed to load discoveries');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const validateCIDR = (cidr: string): boolean => {
    const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-2]?[0-9]|3[0-2])$/;
    return cidrRegex.test(cidr.trim());
  };

  const startDiscovery = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validate CIDR format
    if (!newDiscovery.network_cidr.trim()) {
      setError('Please enter a network CIDR');
      return;
    }
    
    if (!validateCIDR(newDiscovery.network_cidr)) {
      setError('Please enter a valid CIDR format (e.g., 192.168.1.0/24)');
      return;
    }
    
    try {
      setLoading(true);
      setError(null);
      
      const response = await apiService.startNetworkDiscovery({
        network_cidr: newDiscovery.network_cidr.trim(),
        discovery_protocol: newDiscovery.discovery_protocol
      });
      
      // Reset form
      setNewDiscovery({ network_cidr: '', discovery_protocol: 'snmp' });
      
      // Reload discoveries
      await loadDiscoveries();
      
      alert(`Discovery started successfully! ID: ${response.discovery_id}`);
    } catch (err) {
      setError('Failed to start discovery');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-success';
      case 'running': return 'text-warning';
      case 'failed': return 'text-error';
      default: return 'text-info';
    }
  };

  return (
    <div className="container mx-auto p-4">
      <h2 className="text-2xl font-bold mb-6">Network Discovery</h2>
      
      {/* Start New Discovery */}
      <div className="card bg-base-100 shadow-xl mb-6">
        <div className="card-body">
          <h3 className="card-title">Start New Discovery</h3>
          <form onSubmit={startDiscovery} className="space-y-4">
            <div className="form-control">
              <label className="label">
                <span className="label-text">Network CIDR</span>
              </label>
              <input
                type="text"
                placeholder="e.g., 192.168.1.0/24"
                className="input input-bordered"
                value={newDiscovery.network_cidr}
                onChange={(e) => setNewDiscovery({...newDiscovery, network_cidr: e.target.value.trim()})}
                required
              />
            </div>
            
            <div className="form-control">
              <label className="label">
                <span className="label-text">Discovery Protocol</span>
              </label>
              <select
                className="select select-bordered"
                value={newDiscovery.discovery_protocol}
                onChange={(e) => setNewDiscovery({...newDiscovery, discovery_protocol: e.target.value})}
              >
                <option value="snmp">SNMP</option>
                <option value="cdp">CDP</option>
                <option value="lldp">LLDP</option>
                <option value="arp">ARP</option>
                <option value="ping">Ping</option>
                <option value="nmap">Nmap</option>
              </select>
            </div>
            
            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading}
            >
              {loading ? 'Starting...' : 'Start Discovery'}
            </button>
          </form>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="alert alert-error mb-4">
          <span>{error}</span>
        </div>
      )}

      {/* Discovery History */}
      <div className="card bg-base-100 shadow-xl">
        <div className="card-body">
          <h3 className="card-title">Discovery History</h3>
          
          {loading ? (
            <div className="flex justify-center">
              <span className="loading loading-spinner loading-lg"></span>
            </div>
          ) : discoveries.length === 0 ? (
            <p className="text-center text-gray-500">No discoveries found</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="table table-zebra">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Network</th>
                    <th>Protocol</th>
                    <th>Status</th>
                    <th>Devices Found</th>
                    <th>Devices Added</th>
                    <th>Start Time</th>
                    <th>End Time</th>
                  </tr>
                </thead>
                <tbody>
                  {discoveries.map((discovery) => (
                    <tr key={discovery.id}>
                      <td>{discovery.name}</td>
                      <td>{discovery.network_cidr}</td>
                      <td>{discovery.protocol}</td>
                      <td>
                        <span className={`badge ${getStatusColor(discovery.status)}`}>
                          {discovery.status}
                        </span>
                      </td>
                      <td>{discovery.devices_found}</td>
                      <td>{discovery.devices_added}</td>
                      <td>{new Date(discovery.start_time).toLocaleString()}</td>
                      <td>
                        {discovery.end_time 
                          ? new Date(discovery.end_time).toLocaleString()
                          : '-'
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default NetworkDiscoveryComponent;
