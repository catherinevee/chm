import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api/v1';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000, // 30 second timeout for API calls
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor for retry logic
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const config = error.config;
    
    // Retry logic for network errors and timeouts
    if (
      !config._retry && 
      (error.code === 'ECONNABORTED' || error.response?.status >= 500)
    ) {
      config._retry = true;
      config._retryCount = (config._retryCount || 0) + 1;
      
      if (config._retryCount <= 3) {
        // Exponential backoff: 1s, 2s, 4s
        const delay = Math.pow(2, config._retryCount - 1) * 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
        return api(config);
      }
    }
    
    return Promise.reject(error);
  }
);

// Enhanced interfaces for comprehensive inventory management
export interface Device {
  id: string;
  name: string;
  hostname: string;
  ip_address: string;
  device_type: string;
  status: string;
  current_state: string;
  last_poll_time: string | null;
  last_seen?: string;
  consecutive_failures: number;
  circuit_breaker_trips?: number;
  
  // Enhanced inventory fields
  serial_number?: string;
  model?: string;
  manufacturer?: string;
  firmware_version?: string;
  os_name?: string;
  os_version?: string;
  purchase_date?: string;
  warranty_expiry?: string;
  location?: string;
  rack_position?: string;
  data_center?: string;
  department?: string;
  owner?: string;
  cost?: number;
  asset_tag?: string;
  asset_status?: string;
  notes?: string;
  uptime?: string;
  response_time?: number;
  snmp_status?: string;
  
  // Component relationships
  hardware_components?: HardwareComponent[];
  software_components?: SoftwareComponent[];
  network_interfaces?: NetworkInterfaceDetails[];
  device_group?: string;
  custom_group?: string;
  last_maintenance?: string;
  next_maintenance?: string;
  created_at: string;
  updated_at: string;
  

}



export interface Alert {
  id: string;
  device_id: string;
  severity: string;
  metric_name: string;
  metric_value: number;
  message: string;
  created_at: string;
  acknowledged: boolean;
  resolved: boolean;
}

export interface HardwareComponent {
  id: string;
  device_id: string;
  component_type: string;
  name: string;
  description?: string;
  part_number?: string;
  serial_number?: string;
  firmware_version?: string;
  status: string;
  position?: string;
  capacity?: string;
  manufacturer?: string;
  model?: string;
  health_status?: string;
  temperature?: number;
  power_consumption?: number;
  metadata?: any;
  created_at?: string;
  updated_at?: string;
}

export interface SoftwareComponent {
  id: string;
  device_id: string;
  name?: string;
  software_name: string;
  version?: string;
  component_type: string;
  description?: string;
  vendor?: string;
  install_date?: string;
  status: string;
  license_info?: string;
  license_expiry?: string;
  size?: number;
  path?: string;
  checksum?: string;
  metadata?: any;
  created_at?: string;
  updated_at?: string;
}

export interface NetworkInterfaceDetails {
  id: string;
  device_id: string;
  interface_name: string;
  interface_type: string;
  ip_address?: string;
  mac_address?: string;
  status: string;
  speed?: number;
  duplex?: string;
  mtu?: number;
  in_octets?: number;
  out_octets?: number;
  in_errors?: number;
  out_errors?: number;
  description?: string;
  vlan_id?: number;
  is_trunk?: boolean;
  admin_status?: string;
  oper_status?: string;
  last_change?: string;
  metadata?: any;
}

export interface Notification {
  id: string;
  title: string;
  message: string;
  type: string;
  severity: string;
  status: string;
  created_at: string;
  read_at?: string;
  action_url?: string;
  metadata?: any;
  device?: {
    id: string;
    hostname: string;
    ip_address: string;
  };
  alert?: {
    id: string;
    metric_name: string;
    severity: string;
  };
}

export interface NotificationsResponse {
  success: boolean;
  notifications: Notification[];
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
}

export interface Metric {
  timestamp: string;
  cpu: number;
  memory_free: number;
  temperature: number;
}

// Network Discovery interfaces
export interface NetworkDiscovery {
  id: string;
  name: string;
  network_cidr: string;
  protocol: string;
  status: string;
  devices_found: number;
  devices_added: number;
  start_time: string;
  end_time?: string;
  error_message?: string;
}

export interface DiscoveryListResponse {
  discoveries: NetworkDiscovery[];
}

// Network Topology interfaces
export interface DeviceRelationship {
  id: string;
  parent_device_id: string;
  child_device_id: string;
  relationship_type: string;
  parent_interface?: string;
  child_interface?: string;
  bandwidth?: number;
  latency?: number;
}

export interface NetworkTopology {
  devices: Array<{
    id: string;
    hostname: string;
    ip_address: string;
    device_type: string;
    status: string;
    location?: string;
    interfaces: Array<{
      name: string;
      ip_address?: string;
      mac_address?: string;
      status: string;
      speed?: number;
    }>;
  }>;
  relationships: DeviceRelationship[];
}

// SLA Monitoring interfaces
export interface SLAMetric {
  id: string;
  sla_name: string;
  sla_type: string;
  target_value: number;
  current_value?: number;
  uptime_percentage?: number;
  downtime_minutes?: number;
  total_outages: number;
  sla_status?: string;
  last_measurement?: string;
}

export interface DeviceSLAMetrics {
  device_id: string;
  device_hostname: string;
  sla_metrics: SLAMetric[];
}

// Performance Metrics interfaces
export interface PerformanceMetric {
  id: string;
  metric_type: string;
  metric_name: string;
  metric_value: number;
  metric_unit?: string;
  interface_name?: string;
  threshold_warning?: number;
  threshold_critical?: number;
  timestamp: string;
}

export interface DevicePerformanceMetrics {
  device_id: string;
  device_hostname: string;
  time_range_hours: number;
  metrics: PerformanceMetric[];
}

export interface PerformanceGraphData {
  device_id: string;
  device_hostname: string;
  metric_type: string;
  time_range_hours: number;
  interval_minutes: number;
  data_points: Array<{
    timestamp: string;
    value: number;
    unit?: string;
  }>;
}

export interface PerformanceSummary {
  summary: Array<{
    device_id: string;
    device_hostname: string;
    metric_type: string;
    metric_name: string;
    current_value: number;
    unit?: string;
    timestamp: string;
    status: string;
  }>;
  total_devices: number;
  total_metrics: number;
}

export interface DeviceMetrics {
  timestamp: string;
  cpu_usage?: number;
  memory_usage?: number;
  network_usage?: number;
  temperature?: number;
}

export interface DeviceMetricsResponse {
  device_id: string;
  metrics: DeviceMetrics[];
}

export interface PaginationInfo {
  page: number;
  limit: number;
  total: number;
  pages: number;
}

export interface DeviceListResponse {
  devices: Device[];
  pagination: PaginationInfo;
}

export interface Asset {
  id: string;
  hostname: string;
  asset_tag?: string;
  serial_number?: string;
  manufacturer?: string;
  model?: string;
  asset_status?: string;
  location?: string;
  department?: string;
  owner?: string;
  cost?: number;
  purchase_date?: string;
  warranty_expiry?: string;
}

export interface AssetListResponse {
  assets: Asset[];
  pagination: PaginationInfo;
}

export interface CapacityData {
  device_id: string;
  hostname: string;
  capacity_data: {
    metric_type: string;
    current_utilization: number;
    peak_utilization?: number;
    average_utilization?: number;
    threshold_warning: number;
    threshold_critical: number;
    capacity_total?: number;
    capacity_available?: number;
    growth_rate?: number;
    projected_exhaustion?: string;
    recommendations?: string;
    measured_at: string;
  }[];
}

export interface DataArchive {
  id: string;
  archive_type: string;
  source_table: string;
  archive_date: string;
  data_range_start: string;
  data_range_end: string;
  record_count?: number;
  archive_size?: number;
  compression_ratio?: number;
  retention_policy?: string;
  expires_at?: string;
  status: string;
}

export interface BackupLog {
  id: string;
  backup_type: string;
  backup_date: string;
  backup_size?: number;
  duration?: number;
  status: string;
  storage_location?: string;
  checksum?: string;
  error_message?: string;
}

export interface SystemNotification {
  id: string;
  notification_type: string;
  title: string;
  message: string;
  severity: string;
  read: boolean;
  read_at?: string;
  expires_at?: string;
  created_at: string;
}

export const apiService = {
  // Enhanced Device endpoints
  getDevices: async (params?: {
    page?: number;
    limit?: number;
    search?: string;
    device_type?: string;
    status?: string;
    group?: string;
    location?: string;
    manufacturer?: string;
  }): Promise<DeviceListResponse> => {
    const response = await api.get('/devices', { params });
    return response.data;
  },

  getDevice: async (deviceId: string): Promise<Device> => {
    const response = await api.get(`/devices/${deviceId}`);
    return response.data;
  },

        createDevice: async (deviceData: Partial<Device>): Promise<{ message: string; device_id: string }> => {
        const response = await api.post('/devices', deviceData);
        return response.data;
      },

      updateDevice: async (deviceId: string, deviceData: Partial<Device>): Promise<{ message: string; device_id: string }> => {
        const response = await api.put(`/devices/${deviceId}`, deviceData);
        return response.data;
      },

      deleteDevice: async (deviceId: string): Promise<{ message: string; device_id: string }> => {
        const response = await api.delete(`/devices/${deviceId}`);
        return response.data;
      },

  triggerPoll: async (deviceId: string): Promise<{ message: string }> => {
    const response = await api.post(`/devices/${deviceId}/poll`);
    return response.data;
  },

        // Asset Management endpoints
      getAssets: async (params?: {
        page?: number;
        limit?: number;
        asset_status?: string;
        manufacturer?: string;
        location?: string;
        department?: string;
      }): Promise<AssetListResponse> => {
        const response = await api.get('/assets', { params });
        return response.data;
      },

      createAsset: async (assetData: Partial<Asset>): Promise<{ message: string; asset_id: string }> => {
        const response = await api.post('/assets', assetData);
        return response.data;
      },

      updateAsset: async (assetId: string, assetData: Partial<Asset>): Promise<{ message: string; asset_id: string }> => {
        const response = await api.put(`/assets/${assetId}`, assetData);
        return response.data;
      },

      deleteAsset: async (assetId: string): Promise<{ message: string; asset_id: string }> => {
        const response = await api.delete(`/assets/${assetId}`);
        return response.data;
      },

  // Capacity Planning endpoints
  getDeviceCapacity: async (deviceId: string): Promise<CapacityData> => {
    const response = await api.get(`/capacity/${deviceId}`);
    return response.data;
  },

  // Metrics endpoints
  getDeviceMetrics: async (deviceId: string, start?: string, end?: string): Promise<DeviceMetricsResponse> => {
    const params = new URLSearchParams();
    if (start) params.append('start', start);
    if (end) params.append('end', end);
    
    const response = await api.get(`/metrics/${deviceId}?${params.toString()}`);
    return response.data;
  },

  // Alert endpoints
  getAlerts: async (): Promise<Alert[]> => {
    const response = await api.get('/alerts');
    return response.data.alerts; // Extract just the alerts array from the response
  },

  acknowledgeAlert: async (alertId: string): Promise<{ message: string }> => {
    const response = await api.post(`/alerts/${alertId}/acknowledge`);
    return response.data;
  },

  // Data Management endpoints
  getDataArchives: async (): Promise<{ archives: DataArchive[] }> => {
    const response = await api.get('/data/archives');
    return response.data;
  },

  getBackupLogs: async (): Promise<{ backups: BackupLog[] }> => {
    const response = await api.get('/data/backups');
    return response.data;
  },

  exportData: async (exportRequest: {
    data_type: string;
    format: string;
    filters?: Record<string, any>;
  }): Promise<{ format: string; data: any; filename: string }> => {
    const response = await api.post('/data/export', exportRequest);
    return response.data;
  },

  // System Notifications endpoints
  getNotifications: async (user?: string): Promise<{ notifications: SystemNotification[] }> => {
    const params = user ? { user } : {};
    const response = await api.get('/notifications', { params });
    return response.data;
  },

  markNotificationRead: async (notificationId: string): Promise<{ message: string }> => {
    const response = await api.post(`/notifications/${notificationId}/read`);
    return response.data;
  },

  // CSV Import endpoints
  importCsv: async (file: File, hasHeader: boolean = true): Promise<{
    success: boolean;
    imported_count: number;
    imported_devices: Array<{ hostname: string; ip_address: string; id: string }>;
    errors: string[];
    total_rows: number;
  }> => {
    console.log('API Service: Starting CSV import');
    console.log('API Service: File details:', { name: file.name, size: file.size, type: file.type });
    console.log('API Service: Has header:', hasHeader);
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('has_header', hasHeader.toString());
    
    console.log('API Service: FormData created, making request to:', '/import/csv');
    
    try {
      const response = await api.post('/import/csv', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      console.log('API Service: Response received:', response.data);
      return response.data;
    } catch (error) {
      console.error('API Service: Request failed:', error);
      throw error;
    }
  },

  getImportTemplate: async (formatType: string = 'csv'): Promise<{
    format: string;
    filename: string;
    content: string;
    description: string;
    required_fields: string[];
    optional_fields: string[];
    device_types: string[];
    asset_statuses: string[];
    device_groups: string[];
  }> => {
    const response = await api.get(`/import/template/${formatType}`);
    return response.data;
  },

  // Network Discovery endpoints
  startNetworkDiscovery: async (params: {
    network_cidr: string;
    discovery_protocol?: string;
    scan_options?: Record<string, any>;
  }): Promise<{ discovery_id: string; status: string; network_cidr: string; protocol: string }> => {
    const formData = new FormData();
    formData.append('network_cidr', params.network_cidr);
    formData.append('discovery_protocol', params.discovery_protocol || 'snmp');
    if (params.scan_options) {
      formData.append('scan_options', JSON.stringify(params.scan_options));
    }
    
    const response = await api.post('/discovery/start', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  getDiscoveryStatus: async (discoveryId: string): Promise<NetworkDiscovery> => {
    const response = await api.get(`/discovery/${discoveryId}`);
    return response.data;
  },

  listDiscoveries: async (): Promise<DiscoveryListResponse> => {
    const response = await api.get('/discovery');
    return response.data;
  },

  // Network Topology endpoints
  getNetworkTopology: async (): Promise<NetworkTopology> => {
    const response = await api.get('/topology');
    return response.data;
  },

  createDeviceRelationship: async (relationshipData: {
    parent_device_id: string;
    child_device_id: string;
    relationship_type: string;
    parent_interface?: string;
    child_interface?: string;
    bandwidth?: number;
    latency?: number;
    discovery_protocol?: string;
  }): Promise<{ message: string; relationship_id: string }> => {
    const response = await api.post('/topology/relationships', relationshipData);
    return response.data;
  },

  // SLA Monitoring endpoints
  createSLAMetric: async (slaData: {
    device_id: string;
    sla_name: string;
    sla_type: string;
    target_value: number;
    measurement_period?: number;
  }): Promise<{ message: string; sla_id: string }> => {
    const response = await api.post('/sla/metrics', slaData);
    return response.data;
  },

  getDeviceSLAMetrics: async (deviceId: string): Promise<DeviceSLAMetrics> => {
    const response = await api.get(`/sla/metrics/${deviceId}`);
    return response.data;
  },

  updateSLAMetric: async (slaId: string, slaData: {
    current_value?: number;
    uptime_percentage?: number;
    downtime_minutes?: number;
    total_outages?: number;
    sla_status?: string;
  }): Promise<{ message: string; sla_id: string }> => {
    const response = await api.put(`/sla/metrics/${slaId}`, slaData);
    return response.data;
  },

  // Performance Metrics endpoints
  createPerformanceMetric: async (metricData: {
    device_id: string;
    metric_type: string;
    metric_name: string;
    metric_value: number;
    metric_unit?: string;
    interface_name?: string;
    threshold_warning?: number;
    threshold_critical?: number;
  }): Promise<{ message: string; metric_id: string }> => {
    const response = await api.post('/metrics/performance', metricData);
    return response.data;
  },

  getDevicePerformanceMetrics: async (
    deviceId: string,
    metricType?: string,
    hours?: number
  ): Promise<DevicePerformanceMetrics> => {
    const params = new URLSearchParams();
    if (metricType) params.append('metric_type', metricType);
    if (hours) params.append('hours', hours.toString());
    
    const response = await api.get(`/metrics/performance/${deviceId}?${params.toString()}`);
    return response.data;
  },

  getPerformanceGraphData: async (
    deviceId: string,
    metricType: string,
    hours?: number,
    interval?: number
  ): Promise<PerformanceGraphData> => {
    const params = new URLSearchParams();
    params.append('metric_type', metricType);
    if (hours) params.append('hours', hours.toString());
    if (interval) params.append('interval', interval.toString());
    
    const response = await api.get(`/metrics/performance/${deviceId}/graph?${params.toString()}`);
    return response.data;
  },

  getPerformanceSummary: async (): Promise<PerformanceSummary> => {
    const response = await api.get('/metrics/performance/summary');
    return response.data;
  },

  // Health check
  getHealth: async (): Promise<{ status: string }> => {
    const response = await api.get('/health');
    return response.data;
  },



  createNotification: async (notificationData: {
    title: string;
    message: string;
    type?: string;
    severity?: string;
    device_id?: string;
    alert_id?: string;
    user_id?: string;
    metadata?: any;
    action_url?: string;
    expires_at?: string;
  }): Promise<{ success: boolean; notification: Notification }> => {
    const response = await api.post('/notifications', notificationData);
    return response.data;
  },

  // Test notification (for development)
  createTestNotification: async (): Promise<{ success: boolean; notification_id: string; message: string }> => {
    const response = await api.post('/notifications/test');
    return response.data;
  },



  triggerTopologyDiscovery: async (networkCidr?: string): Promise<{
    success: boolean;
    discovery_id?: string;
    network_cidr?: string;
    devices_found?: number;
    devices_added?: number;
    message: string;
  }> => {
    const response = await api.post('/topology/discover', 
      networkCidr ? { network_cidr: networkCidr } : {}
    );
    return response.data;
  },

  startTopologyMonitoring: async (): Promise<{ message: string }> => {
    const response = await api.post('/topology/monitoring/start');
    return response.data;
  },

  stopTopologyMonitoring: async (): Promise<{ message: string }> => {
    const response = await api.post('/topology/monitoring/stop');
    return response.data;
  },

  // Hardware & Software Components
  getDeviceComponents: async (deviceId: string): Promise<{
    hardware_components: HardwareComponent[];
    software_components: SoftwareComponent[];
    network_interfaces: NetworkInterfaceDetails[];
  }> => {
    const response = await api.get(`/devices/${deviceId}/components`);
    return response.data;
  },

  getHardwareComponents: async (deviceId: string): Promise<{ components: HardwareComponent[] }> => {
    const response = await api.get(`/devices/${deviceId}/hardware`);
    return response.data;
  },

  getSoftwareComponents: async (deviceId: string): Promise<{ components: SoftwareComponent[] }> => {
    const response = await api.get(`/devices/${deviceId}/software`);
    return response.data;
  },

  getNetworkInterfaces: async (deviceId: string): Promise<{ interfaces: NetworkInterfaceDetails[] }> => {
    const response = await api.get(`/devices/${deviceId}/interfaces`);
    return response.data;
  },

  triggerComponentDiscovery: async (deviceId: string): Promise<{
    success: boolean;
    message: string;
    components_discovered?: {
      hardware: number;
      software: number;
      interfaces: number;
    };
  }> => {
    const response = await api.post(`/devices/${deviceId}/discover-components`);
    return response.data;
  },
};

export default apiService;
