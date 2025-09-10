import React, { useState } from 'react';

interface DiscoveryResult {
  success: boolean;
  devices: Array<{
    ip_address: string;
    hostname?: string;
    device_type?: string;
    vendor?: string;
    model?: string;
    snmp_community?: string;
    snmp_version?: string;
    ssh_enabled: boolean;
    telnet_enabled: boolean;
    http_enabled: boolean;
    https_enabled: boolean;
    mac_address?: string;
    discovery_time?: string;
  }>;
}

interface ImportResult {
  success: boolean;
  result: {
    total_rows: number;
    successful_imports: number;
    failed_imports: number;
    errors: string[];
    imported_devices: Array<{
      id: string;
      hostname: string;
      ip_address: string;
      device_type: string;
      status: string;
    }>;
  };
}

const DeviceDiscovery: React.FC = () => {
  const [networkCidr, setNetworkCidr] = useState('');
  const [scanType, setScanType] = useState('standard');
  const [discoveryResult, setDiscoveryResult] = useState<DiscoveryResult | null>(null);
  const [importResult, setImportResult] = useState<ImportResult | null>(null);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [importType, setImportType] = useState('csv');

  const validateCIDR = (cidr: string): boolean => {
    const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-2]?[0-9]|3[0-2])$/;
    return cidrRegex.test(cidr.trim());
  };

  const handleDiscovery = async () => {
    const trimmedCidr = networkCidr.trim();
    
    if (!trimmedCidr) {
      alert('Please enter a network CIDR (e.g., 192.168.1.0/24)');
      return;
    }

    if (!validateCIDR(trimmedCidr)) {
      alert('Please enter a valid CIDR format (e.g., 192.168.1.0/24)');
      return;
    }

    setIsDiscovering(true);
    try {
      const formData = new FormData();
      formData.append('network_cidr', networkCidr.trim());
      formData.append('scan_type', scanType);

      const response = await fetch('/api/v1/discover', {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();
      setDiscoveryResult(result);
    } catch (error) {
      console.error('Discovery failed:', error);
      alert('Discovery failed. Please check the network range and try again.');
    } finally {
      setIsDiscovering(false);
    }
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleImport = async () => {
    if (!selectedFile) {
      alert('Please select a file to import');
      return;
    }

    setIsImporting(true);
    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('has_header', 'true');

      const response = await fetch(`/api/v1/import/${importType}`, {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();
      setImportResult(result);
    } catch (error) {
      console.error('Import failed:', error);
      alert('Import failed. Please check the file format and try again.');
    } finally {
      setIsImporting(false);
    }
  };

  const downloadTemplate = async (format: string) => {
    try {
      const response = await fetch(`/api/v1/import/template/${format}`);
      const result = await response.json();
      
      if (result.success) {
        const blob = new Blob([result.template], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `device_import_template.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (error) {
      console.error('Template download failed:', error);
      alert('Failed to download template');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h1 className="text-4xl font-bold">Device Discovery & Import</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Network Discovery */}
        <div className="bg-base-100 shadow-xl rounded-lg p-6">
          <h2 className="text-2xl font-bold mb-4">Network Discovery</h2>
          
          <div className="space-y-4">
            <div>
              <label className="label">
                <span className="label-text">Network CIDR</span>
              </label>
              <input
                type="text"
                placeholder="192.168.1.0/24"
                className="input input-bordered w-full"
                value={networkCidr}
                onChange={(e) => setNetworkCidr(e.target.value)}
              />
            </div>

            <div>
              <label className="label">
                <span className="label-text">Scan Type</span>
              </label>
              <select
                className="select select-bordered w-full"
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
              >
                <option value="quick">Quick Scan</option>
                <option value="standard">Standard Scan</option>
                <option value="comprehensive">Comprehensive Scan</option>
              </select>
            </div>

            <button
              className="btn btn-primary w-full"
              onClick={handleDiscovery}
              disabled={isDiscovering}
            >
              {isDiscovering ? (
                <>
                  <span className="loading loading-spinner loading-sm"></span>
                  Discovering...
                </>
              ) : (
                'Discover Devices'
              )}
            </button>
          </div>

          {/* Discovery Results */}
          {discoveryResult && (
            <div className="mt-6">
              <h3 className="text-lg font-bold mb-2">Discovery Results</h3>
              <div className="bg-base-200 rounded-lg p-4">
                <p className="text-sm">
                  Found {discoveryResult.devices.length} devices
                </p>
                <div className="mt-2 space-y-2">
                  {discoveryResult.devices.map((device, index) => (
                    <div key={index} className="bg-base-100 rounded p-2">
                      <div className="flex justify-between items-center">
                        <div>
                          <p className="font-semibold">{device.ip_address}</p>
                          <p className="text-sm text-base-content/60">
                            {device.hostname || 'Unknown hostname'} • {device.vendor || 'Unknown vendor'} {device.model || ''}
                          </p>
                        </div>
                        <div className="flex gap-1">
                          {device.ssh_enabled && <div className="badge badge-success">SSH</div>}
                          {device.snmp_community && <div className="badge badge-info">SNMP</div>}
                          {device.http_enabled && <div className="badge badge-warning">HTTP</div>}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Bulk Import */}
        <div className="bg-base-100 shadow-xl rounded-lg p-6">
          <h2 className="text-2xl font-bold mb-4">Bulk Import</h2>
          
          <div className="space-y-4">
            <div>
              <label className="label">
                <span className="label-text">Import Type</span>
              </label>
              <select
                className="select select-bordered w-full"
                value={importType}
                onChange={(e) => setImportType(e.target.value)}
              >
                <option value="csv">CSV</option>
                <option value="excel">Excel</option>
                <option value="json">JSON</option>
              </select>
            </div>

            <div>
              <label className="label">
                <span className="label-text">File</span>
              </label>
              <input
                type="file"
                className="file-input file-input-bordered w-full"
                accept={importType === 'csv' ? '.csv' : importType === 'excel' ? '.xlsx,.xls' : '.json'}
                onChange={handleFileSelect}
              />
            </div>

            <div className="flex gap-2">
              <button
                className="btn btn-outline flex-1"
                onClick={() => downloadTemplate(importType)}
              >
                Download Template
              </button>
              <button
                className="btn btn-primary flex-1"
                onClick={handleImport}
                disabled={isImporting || !selectedFile}
              >
                {isImporting ? (
                  <>
                    <span className="loading loading-spinner loading-sm"></span>
                    Importing...
                  </>
                ) : (
                  'Import Devices'
                )}
              </button>
            </div>
          </div>

          {/* Import Results */}
          {importResult && (
            <div className="mt-6">
              <h3 className="text-lg font-bold mb-2">Import Results</h3>
              <div className="bg-base-200 rounded-lg p-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p>Total Rows: {importResult.result.total_rows}</p>
                    <p className="text-success">Successful: {importResult.result.successful_imports}</p>
                  </div>
                  <div>
                    <p className="text-error">Failed: {importResult.result.failed_imports}</p>
                  </div>
                </div>
                
                {importResult.result.errors.length > 0 && (
                  <div className="mt-4">
                    <p className="font-semibold text-error">Errors:</p>
                    <div className="bg-base-100 rounded p-2 max-h-32 overflow-y-auto">
                      {importResult.result.errors.map((error, index) => (
                        <p key={index} className="text-sm text-error">{error}</p>
                      ))}
                    </div>
                  </div>
                )}

                {importResult.result.imported_devices.length > 0 && (
                  <div className="mt-4">
                    <p className="font-semibold text-success">Imported Devices:</p>
                    <div className="bg-base-100 rounded p-2 max-h-32 overflow-y-auto">
                      {importResult.result.imported_devices.map((device, index) => (
                        <p key={index} className="text-sm">
                          {device.hostname} ({device.ip_address}) - {device.device_type}
                        </p>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DeviceDiscovery;
