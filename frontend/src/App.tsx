import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import Dashboard from './components/Dashboard/Dashboard';
import DeviceDetails from './components/DeviceDetails/DeviceDetails';
import Alerts from './components/Alerts/Alerts';
import DeviceDiscovery from './components/DeviceDiscovery/DeviceDiscovery';
import InventoryTab from './components/InventoryTab';
import DeviceList from './components/DeviceList';
import NetworkDiscoveryComponent from './components/NetworkDiscovery';
import NetworkTopologyComponent from './components/NetworkTopology';
import SLAMonitoringComponent from './components/SLAMonitoring';
import PerformanceGraphsComponent from './components/PerformanceGraphs';
import NotificationCenter from './components/Notifications/NotificationCenter';

function App() {
  return (
    <div data-theme="cyberpunk">
      <Router>
        <div className="min-h-screen bg-base-100">
          {/* Navbar */}
          <div className="navbar bg-base-200 shadow-lg">
            <div className="navbar-start">
              <div className="dropdown">
                <div tabIndex={0} role="button" className="btn btn-ghost lg:hidden">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h8m-8 6h16" />
                  </svg>
                </div>
                <ul tabIndex={0} className="menu menu-sm dropdown-content mt-3 z-[1] p-2 shadow bg-base-100 rounded-box w-52">
                  <li><Link to="/">Dashboard</Link></li>
                  <li><Link to="/devices">Devices</Link></li>
                  <li><Link to="/inventory">Inventory</Link></li>
                  <li><Link to="/discovery">Discovery</Link></li>
                  <li><Link to="/network-discovery">Network Discovery</Link></li>
                  <li><Link to="/topology">Topology</Link></li>
                  <li><Link to="/sla">SLA Monitoring</Link></li>
                  <li><Link to="/performance">Performance</Link></li>
                  <li><Link to="/alerts">Alerts</Link></li>
                </ul>
              </div>
              <Link to="/" className="btn btn-ghost text-xl">
                <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Catalyst Health Monitor
              </Link>
            </div>
            <div className="navbar-center hidden lg:flex">
              <ul className="menu menu-horizontal px-1">
                <li><Link to="/" className="link link-hover">Dashboard</Link></li>
                <li><Link to="/devices" className="link link-hover">Devices</Link></li>
                <li><Link to="/inventory" className="link link-hover">Inventory</Link></li>
                <li><Link to="/discovery" className="link link-hover">Discovery</Link></li>
                <li><Link to="/network-discovery" className="link link-hover">Network Discovery</Link></li>
                <li><Link to="/topology" className="link link-hover">Topology</Link></li>
                <li><Link to="/sla" className="link link-hover">SLA</Link></li>
                <li><Link to="/performance" className="link link-hover">Performance</Link></li>
                <li><Link to="/alerts" className="link link-hover">Alerts</Link></li>
              </ul>
            </div>
            <div className="navbar-end">
              <NotificationCenter />
            </div>
          </div>
          
          {/* Main Content */}
          <div className="container mx-auto px-4 py-6">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/device/:deviceId" element={<DeviceDetails />} />
              <Route path="/devices" element={<DeviceList />} />
              <Route path="/inventory" element={<InventoryTab />} />
              <Route path="/discovery" element={<DeviceDiscovery />} />
              <Route path="/network-discovery" element={<NetworkDiscoveryComponent />} />
              <Route path="/topology" element={<NetworkTopologyComponent />} />
              <Route path="/sla" element={<SLAMonitoringComponent />} />
              <Route path="/performance" element={<PerformanceGraphsComponent />} />
              <Route path="/alerts" element={<Alerts />} />
            </Routes>
          </div>
        </div>
      </Router>
    </div>
  );
}

export default App;
