import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { X, Server, Network, Shield, Users, Play, Square, RefreshCw } from "lucide-react";

interface PxeConfig {
  server_ip: string;
  dhcp_range_start: string;
  dhcp_range_end: string;
  subnet_mask: string;
  gateway: string;
  dns_server: string;
  wipe_mode: string;
  auto_shutdown: boolean;
}

interface ClientStatus {
  mac_address: string;
  ip_address: string;
  status: string;
  progress: number;
  timestamp: string;
}

interface PxeBootModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function PxeBootModal({ isOpen, onClose }: PxeBootModalProps) {
  const [config, setConfig] = useState<PxeConfig>({
    server_ip: "192.168.1.100",
    dhcp_range_start: "192.168.1.150",
    dhcp_range_end: "192.168.1.200",
    subnet_mask: "255.255.255.0",
    gateway: "192.168.1.1",
    dns_server: "8.8.8.8",
    wipe_mode: "Quick",
    auto_shutdown: true,
  });

  const [isServerRunning, setIsServerRunning] = useState(false);
  const [clients, setClients] = useState<ClientStatus[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isServerRunning) {
      const interval = setInterval(fetchClientStatuses, 2000);
      return () => clearInterval(interval);
    }
  }, [isServerRunning]);

  const fetchClientStatuses = async () => {
    try {
      const statuses = await invoke<ClientStatus[]>("get_client_statuses");
      setClients(statuses);
    } catch (err) {
      console.error("Failed to fetch client statuses:", err);
    }
  };

  const validateConfig = async () => {
    try {
      await invoke("validate_pxe_config", { config });
      return true;
    } catch (err) {
      setError(`Configuration error: ${err}`);
      return false;
    }
  };

  const startPxeServer = async () => {
    setLoading(true);
    setError("");

    try {
      if (!(await validateConfig())) {
        setLoading(false);
        return;
      }

      await invoke("start_pxe_server", { config });
      setIsServerRunning(true);
      alert("✅ PXE server started successfully!");
    } catch (err) {
      setError(`Failed to start PXE server: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  const stopPxeServer = async () => {
    setLoading(true);
    try {
      await invoke("stop_pxe_server");
      setIsServerRunning(false);
      setClients([]);
      alert("🛑 PXE server stopped");
    } catch (err) {
      setError(`Failed to stop PXE server: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "booting": return "text-blue-400";
      case "wiping": return "text-yellow-400";
      case "completed": return "text-green-400";
      case "failed": return "text-red-400";
      default: return "text-gray-400";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "booting": return "🔄";
      case "wiping": return "🔥";
      case "completed": return "✅";
      case "failed": return "❌";
      default: return "⏳";
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content pxe-modal">
        <div className="modal-header">
          <div className="modal-title">
            <Network className="modal-icon" />
            <span>PXE Boot / Network Wipe</span>
          </div>
          <button onClick={onClose} className="modal-close">
            <X size={20} />
          </button>
        </div>

        <div className="pxe-content">
          {/* Server Configuration */}
          <div className="pxe-section">
            <h3><Server size={18} /> Server Configuration</h3>
            
            <div className="config-grid">
              <div className="config-group">
                <label>Server IP Address</label>
                <input
                  type="text"
                  value={config.server_ip}
                  onChange={(e) => setConfig({...config, server_ip: e.target.value})}
                  disabled={isServerRunning}
                  placeholder="192.168.1.100"
                />
              </div>

              <div className="config-group">
                <label>DHCP Range Start</label>
                <input
                  type="text"
                  value={config.dhcp_range_start}
                  onChange={(e) => setConfig({...config, dhcp_range_start: e.target.value})}
                  disabled={isServerRunning}
                  placeholder="192.168.1.150"
                />
              </div>

              <div className="config-group">
                <label>DHCP Range End</label>
                <input
                  type="text"
                  value={config.dhcp_range_end}
                  onChange={(e) => setConfig({...config, dhcp_range_end: e.target.value})}
                  disabled={isServerRunning}
                  placeholder="192.168.1.200"
                />
              </div>

              <div className="config-group">
                <label>Gateway</label>
                <input
                  type="text"
                  value={config.gateway}
                  onChange={(e) => setConfig({...config, gateway: e.target.value})}
                  disabled={isServerRunning}
                  placeholder="192.168.1.1"
                />
              </div>

              <div className="config-group">
                <label>Wipe Mode</label>
                <select
                  value={config.wipe_mode}
                  onChange={(e) => setConfig({...config, wipe_mode: e.target.value})}
                  disabled={isServerRunning}
                >
                  <option value="Quick">Quick Wipe</option>
                  <option value="DoD">DoD 5220.22-M</option>
                  <option value="Gutmann">Gutmann (35-pass)</option>
                </select>
              </div>

              <div className="config-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={config.auto_shutdown}
                    onChange={(e) => setConfig({...config, auto_shutdown: e.target.checked})}
                    disabled={isServerRunning}
                  />
                  Auto-shutdown after wipe
                </label>
              </div>
            </div>
          </div>

          {/* Server Control */}
          <div className="pxe-section">
            <h3><Shield size={18} /> Server Control</h3>
            
            <div className="server-controls">
              {!isServerRunning ? (
                <button
                  onClick={startPxeServer}
                  disabled={loading}
                  className="btn-primary pxe-btn"
                >
                  <Play size={16} />
                  {loading ? "Starting..." : "Start PXE Server"}
                </button>
              ) : (
                <button
                  onClick={stopPxeServer}
                  disabled={loading}
                  className="btn-danger pxe-btn"
                >
                  <Square size={16} />
                  {loading ? "Stopping..." : "Stop PXE Server"}
                </button>
              )}

              <div className={`server-status ${isServerRunning ? 'running' : 'stopped'}`}>
                <div className="status-indicator"></div>
                {isServerRunning ? "Server Running" : "Server Stopped"}
              </div>
            </div>

            {isServerRunning && (
              <div className="server-info">
                <p><strong>PXE Boot Instructions:</strong></p>
                <ol>
                  <li>Set client laptops to boot from network (PXE)</li>
                  <li>Connect clients to the same network as this server</li>
                  <li>Power on client devices - they will boot automatically</li>
                  <li>Monitor progress below</li>
                </ol>
              </div>
            )}
          </div>

          {/* Client Status */}
          {isServerRunning && (
            <div className="pxe-section">
              <h3>
                <Users size={18} /> 
                Client Status ({clients.length} devices)
                <button onClick={fetchClientStatuses} className="refresh-btn">
                  <RefreshCw size={14} />
                </button>
              </h3>
              
              {clients.length === 0 ? (
                <div className="no-clients">
                  <p>No clients connected yet. Waiting for devices to boot...</p>
                </div>
              ) : (
                <div className="clients-table">
                  <div className="table-header">
                    <span>MAC Address</span>
                    <span>IP Address</span>
                    <span>Status</span>
                    <span>Progress</span>
                    <span>Last Update</span>
                  </div>
                  
                  {clients.map((client, index) => (
                    <div key={index} className="table-row">
                      <span className="mac-address">{client.mac_address}</span>
                      <span>{client.ip_address}</span>
                      <span className={`status ${getStatusColor(client.status)}`}>
                        {getStatusIcon(client.status)} {client.status}
                      </span>
                      <span>
                        <div className="progress-bar">
                          <div 
                            className="progress-fill" 
                            style={{width: `${client.progress}%`}}
                          ></div>
                          <span className="progress-text">{client.progress}%</span>
                        </div>
                      </span>
                      <span className="timestamp">{client.timestamp}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {error && (
            <div className="error-message">
              ❌ {error}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}