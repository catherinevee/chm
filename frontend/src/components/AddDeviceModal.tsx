import React, { useState } from 'react';
import apiService from '../services/api';

interface AddDeviceModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDeviceAdded: () => void;
}

const AddDeviceModal: React.FC<AddDeviceModalProps> = ({ isOpen, onClose, onDeviceAdded }) => {
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

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    // Trim whitespace from text inputs
    const trimmedValue = typeof value === 'string' ? value.trim() : value;
    setFormData(prev => ({
      ...prev,
      [name]: trimmedValue
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      // Validate and convert cost to number if provided
      let cost: number | undefined = undefined;
      if (formData.cost) {
        const parsedCost = parseFloat(formData.cost);
        if (isNaN(parsedCost) || parsedCost < 0) {
          setError('Cost must be a valid positive number');
          return;
        }
        cost = parsedCost;
      }

      const deviceData = {
        ...formData,
        cost
      };

      await apiService.createDevice(deviceData);
      onDeviceAdded();
      onClose();
      setFormData({
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
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to add device');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal modal-open">
      <div className="modal-box max-w-4xl max-h-screen overflow-y-auto">
        <h3 className="font-bold text-lg mb-4">Add New Device</h3>
        
        {error && (
          <div className="alert alert-error mb-4">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Required Fields Section */}
          <div className="card bg-base-200 p-4">
            <h4 className="font-semibold text-lg mb-4 text-primary">Required Information</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Hostname *</span>
                </label>
                <input
                  type="text"
                  name="hostname"
                  value={formData.hostname}
                  onChange={handleInputChange}
                  className="input input-bordered focus:input-primary"
                  required
                  placeholder="device-name"
                />
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">IP Address *</span>
                </label>
                <input
                  type="text"
                  name="ip_address"
                  value={formData.ip_address}
                  onChange={handleInputChange}
                  className="input input-bordered focus:input-primary"
                  required
                  placeholder="192.168.1.1"
                />
              </div>
            </div>
          </div>

          {/* Device Classification Section */}
          <div className="card bg-base-200 p-4">
            <h4 className="font-semibold text-lg mb-4 text-primary">Device Classification</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Device Type</span>
                </label>
                <select
                  name="device_type"
                  value={formData.device_type}
                  onChange={handleInputChange}
                  className="select select-bordered focus:select-primary"
                >
                  <option value="router"> Router</option>
                  <option value="switch"> Switch</option>
                  <option value="firewall"> Firewall</option>
                  <option value="server"> Server</option>
                  <option value="workstation"> Workstation</option>
                  <option value="printer"> Printer</option>
                  <option value="camera"> Camera</option>
                  <option value="sensor"> Sensor</option>
                  <option value="other"> Other</option>
                </select>
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Manufacturer</span>
                </label>
                <select
                  name="manufacturer"
                  value={formData.manufacturer}
                  onChange={handleInputChange}
                  className="select select-bordered focus:select-primary"
                >
                  <option value="">Select Manufacturer</option>
                  <option value="Cisco">Cisco</option>
                  <option value="HP">HP / HPE</option>
                  <option value="Dell">Dell</option>
                  <option value="Juniper">Juniper</option>
                  <option value="Arista">Arista</option>
                  <option value="Fortinet">Fortinet</option>
                  <option value="Palo Alto">Palo Alto Networks</option>
                  <option value="VMware">VMware</option>
                  <option value="Ubiquiti">Ubiquiti</option>
                  <option value="Netgear">Netgear</option>
                  <option value="D-Link">D-Link</option>
                  <option value="TP-Link">TP-Link</option>
                  <option value="Other">Other</option>
                </select>
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Model</span>
                </label>
                <input
                  type="text"
                  name="model"
                  value={formData.model}
                  onChange={handleInputChange}
                  className="input input-bordered focus:input-primary"
                  placeholder="e.g., Catalyst 2960, PowerEdge R740"
                />
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Serial Number</span>
                </label>
                <input
                  type="text"
                  name="serial_number"
                  value={formData.serial_number}
                  onChange={handleInputChange}
                  className="input input-bordered focus:input-primary"
                  placeholder="SN123456789"
                />
              </div>
            </div>
          </div>

          {/* Software Information Section */}
          <div className="card bg-base-200 p-4">
            <h4 className="font-semibold text-lg mb-4 text-primary">Software Information</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Firmware Version</span>
                </label>
                <input
                  type="text"
                  name="firmware_version"
                  value={formData.firmware_version}
                  onChange={handleInputChange}
                  className="input input-bordered focus:input-primary"
                  placeholder="e.g., 15.0(2)SE11, 12.4.3"
                />
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Operating System</span>
                </label>
                <select
                  name="os_version"
                  value={formData.os_version}
                  onChange={handleInputChange}
                  className="select select-bordered focus:select-primary"
                >
                  <option value="">Select OS</option>
                  <option value="IOS">Cisco IOS</option>
                  <option value="IOS-XE">Cisco IOS-XE</option>
                  <option value="NX-OS">Cisco NX-OS</option>
                  <option value="EOS">Arista EOS</option>
                  <option value="JunOS">Juniper JunOS</option>
                  <option value="Windows Server">Windows Server</option>
                  <option value="Linux">Linux</option>
                  <option value="Ubuntu">Ubuntu</option>
                  <option value="CentOS">CentOS</option>
                  <option value="RHEL">Red Hat Enterprise Linux</option>
                  <option value="ESXi">VMware ESXi</option>
                  <option value="FortiOS">FortiOS</option>
                  <option value="PAN-OS">PAN-OS</option>
                  <option value="Other">Other</option>
                </select>
              </div>
            </div>
          </div>

          {/* Physical Location Section */}
          <div className="card bg-base-200 p-4">
            <h4 className="font-semibold text-lg mb-4 text-primary">Physical Location</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Data Center</span>
                </label>
                <select
                  name="data_center"
                  value={formData.data_center}
                  onChange={handleInputChange}
                  className="select select-bordered focus:select-primary"
                >
                  <option value="">Select Data Center</option>
                  <option value="Primary DC"> Primary Data Center</option>
                  <option value="Secondary DC"> Secondary Data Center</option>
                  <option value="DR Site"> Disaster Recovery Site</option>
                  <option value="Edge Location"> Edge Location</option>
                  <option value="Branch Office"> Branch Office</option>
                  <option value="Co-location"> Co-location Facility</option>
                  <option value="Cloud"> Cloud Infrastructure</option>
                  <option value="Other"> Other</option>
                </select>
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Location</span>
                </label>
                <input
                  type="text"
                  name="location"
                  value={formData.location}
                  onChange={handleInputChange}
                  className="input input-bordered focus:input-primary"
                  placeholder="e.g., Building A, Floor 3, Room 301"
                />
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Rack Position</span>
                </label>
                <input
                  type="text"
                  name="rack_position"
                  value={formData.rack_position}
                  onChange={handleInputChange}
                  className="input input-bordered focus:input-primary"
                  placeholder="e.g., Rack 01-U15, R42-U10-U12"
                />
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Department</span>
                </label>
                <select
                  name="department"
                  value={formData.department}
                  onChange={handleInputChange}
                  className="select select-bordered focus:select-primary"
                >
                  <option value="">Select Department</option>
                  <option value="IT"> IT Department</option>
                  <option value="Network Operations"> Network Operations</option>
                  <option value="Security"> Security Team</option>
                  <option value="Infrastructure"> Infrastructure</option>
                  <option value="DevOps"> DevOps</option>
                  <option value="Engineering"> Engineering</option>
                  <option value="Operations"> Operations</option>
                  <option value="Finance"> Finance</option>
                  <option value="HR"> Human Resources</option>
                  <option value="Other"> Other</option>
                </select>
              </div>
            </div>
          </div>

          {/* Asset Management Section */}
          <div className="card bg-base-200 p-4">
            <h4 className="font-semibold text-lg mb-4 text-primary">Asset Management</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Asset Tag</span>
                </label>
                <input
                  type="text"
                  name="asset_tag"
                  value={formData.asset_tag}
                  onChange={handleInputChange}
                  className="input input-bordered focus:input-primary"
                  placeholder="e.g., ASSET-001, IT-SW-001"
                />
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Asset Status</span>
                </label>
                <select
                  name="asset_status"
                  value={formData.asset_status}
                  onChange={handleInputChange}
                  className="select select-bordered focus:select-primary"
                >
                  <option value="active">PASS: Active</option>
                  <option value="inactive"> Inactive</option>
                  <option value="retired"> Retired</option>
                  <option value="lost"> Lost</option>
                  <option value="stolen"> Stolen</option>
                </select>
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Owner</span>
                </label>
                <input
                  type="text"
                  name="owner"
                  value={formData.owner}
                  onChange={handleInputChange}
                  className="input input-bordered focus:input-primary"
                  placeholder="e.g., John Doe, IT Team"
                />
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Cost ($)</span>
                </label>
                <input
                  type="number"
                  name="cost"
                  value={formData.cost}
                  onChange={handleInputChange}
                  className="input input-bordered focus:input-primary"
                  placeholder="2500.00"
                  step="0.01"
                  min="0"
                />
              </div>
            </div>
          </div>

          {/* Network Configuration Section */}
          <div className="card bg-base-200 p-4">
            <h4 className="font-semibold text-lg mb-4 text-primary">Network Configuration</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Device Group</span>
                </label>
                <select
                  name="device_group"
                  value={formData.device_group}
                  onChange={handleInputChange}
                  className="select select-bordered focus:select-primary"
                >
                  <option value="production"> Production</option>
                  <option value="development"> Development</option>
                  <option value="testing"> Testing</option>
                  <option value="dmz"> DMZ</option>
                  <option value="internal"> Internal</option>
                  <option value="external"> External</option>
                </select>
              </div>

              <div className="form-control">
                <label className="label">
                  <span className="label-text font-medium">Custom Group</span>
                </label>
                <input
                  type="text"
                  name="custom_group"
                  value={formData.custom_group}
                  onChange={handleInputChange}
                  className="input input-bordered focus:input-primary"
                  placeholder="e.g., Core Network, Edge Switches"
                />
              </div>
            </div>
          </div>

          {/* Additional Information Section */}
          <div className="card bg-base-200 p-4">
            <h4 className="font-semibold text-lg mb-4 text-primary">Additional Information</h4>
            <div className="form-control">
              <label className="label">
                <span className="label-text font-medium">Notes</span>
              </label>
              <textarea
                name="notes"
                value={formData.notes}
                onChange={handleInputChange}
                className="textarea textarea-bordered focus:textarea-primary"
                placeholder="Additional notes about the device, configuration details, special requirements..."
                rows={4}
              />
            </div>
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
                  Adding...
                </>
              ) : (
                'Add Device'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AddDeviceModal;
