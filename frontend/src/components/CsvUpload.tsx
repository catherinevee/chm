import React, { useState, useRef } from 'react';
import apiService from '../services/api';

interface CsvUploadProps {
  onUploadComplete?: () => void;
  onClose?: () => void;
}

const CsvUpload: React.FC<CsvUploadProps> = ({ onUploadComplete, onClose }) => {
  const [file, setFile] = useState<File | null>(null);
  const [hasHeader, setHasHeader] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<{
    success: boolean;
    imported_count: number;
    imported_devices: Array<{ hostname: string; ip_address: string; id: string }>;
    errors: string[];
    total_rows: number;
  } | null>(null);
  const [template, setTemplate] = useState<{
    content: string;
    filename: string;
    description: string;
    required_fields: string[];
    optional_fields: string[];
    device_types: string[];
    asset_statuses: string[];
    device_groups: string[];
  } | null>(null);
  const [showTemplate, setShowTemplate] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0];
    if (selectedFile && (selectedFile.type === 'text/csv' || selectedFile.name.toLowerCase().endsWith('.csv'))) {
      setFile(selectedFile);
      setUploadResult(null);
    } else if (selectedFile) {
      alert('Please select a valid CSV file');
    }
  };

  const handleUpload = async () => {
    if (!file) {
      alert('Please select a file to upload');
      return;
    }

    setUploading(true);
    try {
      console.log('Starting upload for file:', file.name, 'Size:', file.size, 'Type:', file.type);
      console.log('Has header:', hasHeader);
      
      const result = await apiService.importCsv(file, hasHeader);
      console.log('Upload result:', result);
      setUploadResult(result);
      
      if (result.success && onUploadComplete) {
        onUploadComplete();
      }
    } catch (error: any) {
      console.error('Upload failed:', error);
      console.error('Error details:', {
        message: error.message,
        response: error.response,
        status: error.response?.status,
        data: error.response?.data
      });
      const errorMessage = error.response?.data?.detail || error.message || 'Upload failed. Please check your file and try again.';
      alert(`Upload failed: ${errorMessage}`);
    } finally {
      setUploading(false);
    }
  };

  const handleDownloadTemplate = async () => {
    try {
      const templateData = await apiService.getImportTemplate('csv');
      setTemplate(templateData);
      setShowTemplate(true);
    } catch (error) {
      console.error('Failed to get template:', error);
      alert('Failed to download template');
    }
  };

  const downloadTemplateFile = () => {
    if (!template) return;
    
    const blob = new Blob([template.content], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = template.filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  };

  const resetForm = () => {
    setFile(null);
    setHasHeader(true);
    setUploadResult(null);
    setShowTemplate(false);
    setTemplate(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="card bg-base-100 shadow-lg">
      <div className="card-body">
        <h2 className="card-title text-2xl mb-4">Import Devices from CSV</h2>
        
        {/* Template Download Section */}
        <div className="card bg-base-200 mb-6">
          <div className="card-body">
            <h3 className="card-title text-lg">CSV Template</h3>
            <p className="text-sm opacity-70 mb-4">
              Download a template CSV file with all supported columns and example data.
            </p>
            <div className="flex gap-2">
              <button
                className="btn btn-outline btn-sm"
                onClick={handleDownloadTemplate}
                disabled={uploading}
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Get Template
              </button>
              {template && (
                <button
                  className="btn btn-primary btn-sm"
                  onClick={downloadTemplateFile}
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                  Download Template
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Template Preview */}
        {showTemplate && template && (
          <div className="card bg-base-200 mb-6">
            <div className="card-body">
              <h3 className="card-title text-lg">Template Information</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <h4 className="font-semibold mb-2">Required Fields:</h4>
                  <ul className="list-disc list-inside">
                    {template.required_fields.map(field => (
                      <li key={field} className="text-success">{field}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h4 className="font-semibold mb-2">Optional Fields:</h4>
                  <ul className="list-disc list-inside">
                    {template.optional_fields.map(field => (
                      <li key={field} className="text-info">{field}</li>
                    ))}
                  </ul>
                </div>
              </div>
              <div className="mt-4">
                <h4 className="font-semibold mb-2">Supported Values:</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                  <div>
                    <strong>Device Types:</strong>
                    <div className="mt-1">{template.device_types.join(', ')}</div>
                  </div>
                  <div>
                    <strong>Asset Statuses:</strong>
                    <div className="mt-1">{template.asset_statuses.join(', ')}</div>
                  </div>
                  <div>
                    <strong>Device Groups:</strong>
                    <div className="mt-1">{template.device_groups.join(', ')}</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* File Upload Section */}
        <div className="card bg-base-200 mb-6">
          <div className="card-body">
            <h3 className="card-title text-lg">Upload CSV File</h3>
            
            <div className="form-control mb-4">
              <label className="label">
                <span className="label-text">Select CSV File</span>
              </label>
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv"
                onChange={handleFileSelect}
                className="file-input file-input-bordered w-full"
                disabled={uploading}
              />
              {file && (
                <label className="label">
                  <span className="label-text-alt text-success">
                    Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)
                  </span>
                </label>
              )}
            </div>

            <div className="form-control mb-4">
              <label className="label cursor-pointer">
                <span className="label-text">File has header row</span>
                <input
                  type="checkbox"
                  className="checkbox checkbox-primary"
                  checked={hasHeader}
                  onChange={(e) => setHasHeader(e.target.checked)}
                  disabled={uploading}
                />
              </label>
            </div>

            <div className="flex gap-2">
              <button
                className="btn btn-primary"
                onClick={handleUpload}
                disabled={!file || uploading}
              >
                {uploading ? (
                  <>
                    <span className="loading loading-spinner loading-sm"></span>
                    Uploading...
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                    Upload Devices
                  </>
                )}
              </button>
              <button
                className="btn btn-outline"
                onClick={resetForm}
                disabled={uploading}
              >
                Reset
              </button>
              {onClose && (
                <button
                  className="btn btn-ghost"
                  onClick={onClose}
                  disabled={uploading}
                >
                  Cancel
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Upload Results */}
        {uploadResult && (
          <div className="card bg-base-200">
            <div className="card-body">
              <h3 className="card-title text-lg">
                Upload Results
                <span className={`badge ${uploadResult.success ? 'badge-success' : 'badge-error'}`}>
                  {uploadResult.success ? 'Success' : 'Failed'}
                </span>
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <div className="stat bg-base-100 rounded-lg">
                  <div className="stat-title">Imported</div>
                  <div className="stat-value text-success">{uploadResult.imported_count}</div>
                </div>
                <div className="stat bg-base-100 rounded-lg">
                  <div className="stat-title">Total Rows</div>
                  <div className="stat-value text-info">{uploadResult.total_rows}</div>
                </div>
                <div className="stat bg-base-100 rounded-lg">
                  <div className="stat-title">Errors</div>
                  <div className="stat-value text-error">{uploadResult.errors.length}</div>
                </div>
              </div>

              {uploadResult.imported_devices.length > 0 && (
                <div className="mb-4">
                  <h4 className="font-semibold mb-2">Imported Devices:</h4>
                  <div className="overflow-x-auto">
                    <table className="table table-sm">
                      <thead>
                        <tr>
                          <th>Hostname</th>
                          <th>IP Address</th>
                          <th>ID</th>
                        </tr>
                      </thead>
                      <tbody>
                        {uploadResult.imported_devices.map((device, index) => (
                          <tr key={index}>
                            <td>{device.hostname}</td>
                            <td>{device.ip_address}</td>
                            <td className="text-xs opacity-70">{device.id}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {uploadResult.errors.length > 0 && (
                <div>
                  <h4 className="font-semibold mb-2 text-error">Errors:</h4>
                  <div className="max-h-40 overflow-y-auto">
                    <ul className="list-disc list-inside text-sm">
                      {uploadResult.errors.map((error, index) => (
                        <li key={index} className="text-error">{error}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CsvUpload;
