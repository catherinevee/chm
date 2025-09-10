import React, { useState, useEffect } from 'react';
import apiService, { Device } from '../services/api';

interface EditDeviceModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDeviceUpdated: () => void;
  device: Device | null;
}

const EditDeviceModal: React.FC<EditDeviceModalProps> = ({ isOpen, onClose, onDeviceUpdated, device }) => {
  const [formData, setFormData] = useState({
    hostname: '',
    ip_address: '',
    device_type: 'switch',
    serial_number: '',
    model: '',
    manufacturer: '',
    firmware_version: '',
    os_version: '',
    location: '',
    rack_position: '',
    data_center: '',
    department: '',
    owner: '',
    cost: '',
    asset_tag: '',
    asset_status: 'active',
    device_group: 'production',
    custom_group: '',
    notes: ''
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Update form data when device prop changes
  useEffect(() => {
    if (device) {
      setFormData({
        hostname: device.hostname || '',
        ip_address: device.ip_address || '',
        device_type: device.device_type || 'switch',
        serial_number: device.serial_number || '',
        model: device.model || '',
        manufacturer: device.manufacturer || '',
        firmware_version: device.firmware_version || '',
        os_version: device.os_version || '',
        location: device.location || '',
        rack_position: device.rack_position || '',
        data_center: device.data_center || '',
        department: device.department || '',
        owner: device.owner || '',
        cost: device.cost?.toString() || '',
        asset_tag: device.asset_tag || '',
        asset_status: device.asset_status || 'active',
        device_group: device.device_group || 'production',
        custom_group: device.custom_group || '',
        notes: device.notes || ''
      });
    }
  }, [device]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!device) return;

    setLoading(true);
    setError(null);

    try {
      // Convert cost to number if provided
      const deviceData = {
        ...formData,
        cost: formData.cost ? parseFloat(formData.cost) : undefined
      };

      await apiService.updateDevice(device.id, deviceData);
      onDeviceUpdated();
      onClose();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to update device');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen || !device) return null;

  return (
    <div className="modal modal-open">
      <div className="modal-box max-w-4xl max-h-screen overflow-y-auto">
        <h3 className="font-bold text-lg mb-4">Edit Device - {device.hostname}</h3>
        
        {error && (
          <div className="alert alert-error mb-4">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Required Fields */}
            <div className="form-control">
              <label className="label">
                <span className="label-text">Hostname *</span>
              </label>
              <input
                type="text"
                name="hostname"
                value={formData.hostname}
                onChange={handleInputChange}
                className="input input-bordered"
                required
                placeholder="device-name"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">IP Address *</span>
              </label>
              <input
                type="text"
                name="ip_address"
                value={formData.ip_address}
                onChange={handleInputChange}
                className="input input-bordered"
                required
                placeholder="192.168.1.1"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Device Type</span>
              </label>
              <select
                name="device_type"
                value={formData.device_type}
                onChange={handleInputChange}
                className="select select-bordered"
              >
                <option value="router">Router</option>
                <option value="switch">Switch</option>
                <option value="firewall">Firewall</option>
                <option value="server">Server</option>
                <option value="workstation">Workstation</option>
                <option value="printer">Printer</option>
                <option value="camera">Camera</option>
                <option value="sensor">Sensor</option>
                <option value="other">Other</option>
              </select>
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Serial Number</span>
              </label>
              <input
                type="text"
                name="serial_number"
                value={formData.serial_number}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="SN123456789"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Model</span>
              </label>
              <input
                type="text"
                name="model"
                value={formData.model}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="Cisco Catalyst 2960"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Manufacturer</span>
              </label>
              <input
                type="text"
                name="manufacturer"
                value={formData.manufacturer}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="Cisco"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Firmware Version</span>
              </label>
              <input
                type="text"
                name="firmware_version"
                value={formData.firmware_version}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="15.0(2)SE11"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">OS Version</span>
              </label>
              <input
                type="text"
                name="os_version"
                value={formData.os_version}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="IOS"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Location</span>
              </label>
              <input
                type="text"
                name="location"
                value={formData.location}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="Data Center A"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Rack Position</span>
              </label>
              <input
                type="text"
                name="rack_position"
                value={formData.rack_position}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="Rack 01-01"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Data Center</span>
              </label>
              <input
                type="text"
                name="data_center"
                value={formData.data_center}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="Primary DC"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Department</span>
              </label>
              <input
                type="text"
                name="department"
                value={formData.department}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="Network Team"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Owner</span>
              </label>
              <input
                type="text"
                name="owner"
                value={formData.owner}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="John Doe"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Cost ($)</span>
              </label>
              <input
                type="number"
                name="cost"
                value={formData.cost}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="2500.00"
                step="0.01"
                min="0"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Asset Tag</span>
              </label>
              <input
                type="text"
                name="asset_tag"
                value={formData.asset_tag}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="ASSET-001"
              />
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Asset Status</span>
              </label>
              <select
                name="asset_status"
                value={formData.asset_status}
                onChange={handleInputChange}
                className="select select-bordered"
              >
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
                <option value="retired">Retired</option>
                <option value="lost">Lost</option>
                <option value="stolen">Stolen</option>
              </select>
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Device Group</span>
              </label>
              <select
                name="device_group"
                value={formData.device_group}
                onChange={handleInputChange}
                className="select select-bordered"
              >
                <option value="production">Production</option>
                <option value="development">Development</option>
                <option value="testing">Testing</option>
                <option value="dmz">DMZ</option>
                <option value="internal">Internal</option>
                <option value="external">External</option>
              </select>
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text">Custom Group</span>
              </label>
              <input
                type="text"
                name="custom_group"
                value={formData.custom_group}
                onChange={handleInputChange}
                className="input input-bordered"
                placeholder="Core Network"
              />
            </div>
          </div>

          <div className="form-control">
            <label className="label">
              <span className="label-text">Notes</span>
            </label>
            <textarea
              name="notes"
              value={formData.notes}
              onChange={handleInputChange}
              className="textarea textarea-bordered"
              placeholder="Additional notes about the device..."
              rows={3}
            />
          </div>

          <div className="modal-action">
            <button
              type="button"
              className="btn"
              onClick={onClose}
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
                  Updating...
                </>
              ) : (
                'Update Device'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EditDeviceModal;
