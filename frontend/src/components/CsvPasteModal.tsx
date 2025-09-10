import React, { useState } from 'react';
import apiService from '../services/api';

interface CsvPasteModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImportComplete: () => void;
}

const CsvPasteModal: React.FC<CsvPasteModalProps> = ({ isOpen, onClose, onImportComplete }) => {
  const [csvData, setCsvData] = useState('');
  const [hasHeader, setHasHeader] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{
    success: boolean;
    imported_count: number;
    errors: string[];
    total_rows: number;
  } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!csvData.trim()) {
      setError('Please paste CSV data');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      // Create a File object from the pasted CSV data
      const blob = new Blob([csvData], { type: 'text/csv' });
      const file = new File([blob], 'pasted-data.csv', { type: 'text/csv' });

      const response = await apiService.importCsv(file, hasHeader);
      setResult(response);
      
      if (response.success) {
        onImportComplete();
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to import CSV data');
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setCsvData('');
    setError(null);
    setResult(null);
  };

  const handleClose = () => {
    setCsvData('');
    setHasHeader(true);
    setError(null);
    setResult(null);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="modal modal-open">
      <div className="modal-box max-w-4xl max-h-screen overflow-y-auto">
        <h3 className="font-bold text-lg mb-4">Paste CSV Data</h3>
        
        <div className="mb-4">
          <p className="text-sm text-base-content/70 mb-2">
            Paste your CSV data below. Make sure the first row contains column headers if you have them.
          </p>
          <div className="text-xs text-base-content/60">
            <strong>Required columns:</strong> hostname, ip_address<br/>
            <strong>Optional columns:</strong> device_type, serial_number, model, manufacturer, firmware_version, os_version, location, rack_position, data_center, department, owner, cost, asset_tag, asset_status, device_group, custom_group, notes
          </div>
        </div>

        {error && (
          <div className="alert alert-error mb-4">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>{error}</span>
          </div>
        )}

        {result && (
          <div className={`alert ${result.success ? 'alert-success' : 'alert-warning'} mb-4`}>
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {result.success ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              )}
            </svg>
            <div>
              <div className="font-bold">
                {result.success ? 'Import Completed' : 'Import Completed with Errors'}
              </div>
              <div className="text-sm">
                Imported: {result.imported_count} devices | Total rows: {result.total_rows}
                {result.errors.length > 0 && (
                  <div className="mt-2">
                    <strong>Errors ({result.errors.length}):</strong>
                    <ul className="list-disc list-inside mt-1">
                      {result.errors.slice(0, 5).map((error, index) => (
                        <li key={index} className="text-xs">{error}</li>
                      ))}
                      {result.errors.length > 5 && (
                        <li className="text-xs">... and {result.errors.length - 5} more errors</li>
                      )}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="form-control">
            <label className="label">
              <span className="label-text">CSV Data</span>
            </label>
            <textarea
              value={csvData}
              onChange={(e) => setCsvData(e.target.value)}
              className="textarea textarea-bordered font-mono text-sm"
              placeholder="hostname,ip_address,device_type,serial_number,model,manufacturer,firmware_version,os_version,location,rack_position,data_center,department,owner,cost,asset_tag,asset_status,device_group,custom_group,notes&#10;router-01,10.101.1.1,router,SN123456789,Cisco ISR4321,Cisco,16.9.4,IOS-XE,Data Center A,Rack 01-01,Primary DC,EIS,John Doe,2500.00,ASSET-001,active,production,Core Network,Primary router for office network"
              rows={15}
              required
            />
          </div>

          <div className="form-control">
            <label className="label cursor-pointer">
              <span className="label-text">First row contains headers</span>
              <input
                type="checkbox"
                className="checkbox"
                checked={hasHeader}
                onChange={(e) => setHasHeader(e.target.checked)}
              />
            </label>
          </div>

          <div className="flex gap-2">
            <button
              type="button"
              className="btn btn-outline"
              onClick={handleClear}
              disabled={loading}
            >
              Clear
            </button>
            <button
              type="button"
              className="btn btn-outline"
              onClick={() => {
                const sampleData = `hostname,ip_address,device_type,serial_number,model,manufacturer,firmware_version,os_version,location,rack_position,data_center,department,owner,cost,asset_tag,asset_status,device_group,custom_group,notes
router-01,10.101.1.1,router,SN123456789,Cisco ISR4321,Cisco,16.9.4,IOS-XE,Data Center A,Rack 01-01,Primary DC,EIS,John Doe,2500.00,ASSET-001,active,production,Core Network,Primary router for office network
switch-01,10.101.1.2,switch,SN987654321,HP ProCurve 2920,HP,15.16.0001,ProCurve,Data Center A,Rack 01-02,Primary DC,EIS,Jane Smith,1800.00,ASSET-002,active,production,Access Layer,Access switch for floor 1
firewall-01,10.101.1.3,firewall,SN456789123,FortiGate 60F,Fortinet,7.0.5,FortiOS,Data Center A,Rack 01-03,Primary DC,EIS,Bob Johnson,3200.00,ASSET-003,active,production,DMZ,Perimeter firewall`;
                setCsvData(sampleData);
              }}
              disabled={loading}
            >
              Load Sample
            </button>
          </div>

          <div className="modal-action">
            <button
              type="button"
              className="btn"
              onClick={handleClose}
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="loading loading-spinner loading-sm"></span>
                  Importing...
                </>
              ) : (
                'Import CSV'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CsvPasteModal;
