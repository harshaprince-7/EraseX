import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface GeofenceModalProps {
  isOpen: boolean;
  onClose: () => void;
  sensitiveFiles: string[];
  userId: number;
}

interface LocationStatus {
  inside_geofence: boolean;
  files_locked: boolean;
  last_check: string;
}

const GeofenceModal: React.FC<GeofenceModalProps> = ({ isOpen, onClose, sensitiveFiles, userId }) => {
  const [locations, setLocations] = useState<Array<{lat: number, lon: number, radius: number, name: string}>>([]);
  const [currentLat, setCurrentLat] = useState<string>('');
  const [currentLon, setCurrentLon] = useState<string>('');
  const [currentRadius, setCurrentRadius] = useState<string>('100');
  const [locationName, setLocationName] = useState<string>('');
  const [availableWiFi, setAvailableWiFi] = useState<string[]>([]);
  const [selectedWiFi, setSelectedWiFi] = useState<string[]>([]);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [status, setStatus] = useState<LocationStatus | null>(null);
  const [unlockPin, setUnlockPin] = useState('');
  const [showUnlock, setShowUnlock] = useState(false);

  useEffect(() => {
    if (isOpen) {
      getCurrentLocation();
      scanWiFi();
      checkStatus();
    }
  }, [isOpen]);

  const getCurrentLocation = () => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          setCurrentLat(position.coords.latitude.toString());
          setCurrentLon(position.coords.longitude.toString());
        },
        (error) => console.error('Geolocation error:', error)
      );
    }
  };

  const scanWiFi = async () => {
    try {
      const networks = await invoke<string[]>('scan_wifi_networks');
      setAvailableWiFi(networks);
    } catch (err) {
      console.error('Failed to scan Wi-Fi:', err);
    }
  };

  const checkStatus = async () => {
    try {
      const currentStatus = await invoke<LocationStatus>('get_geofence_status');
      setStatus(currentStatus);
      setShowUnlock(currentStatus.files_locked);
    } catch (err) {
      console.error('Failed to get status:', err);
    }
  };

  const addLocation = () => {
    if (!currentLat || !currentLon || !locationName) {
      alert('Please fill all location fields');
      return;
    }
    
    const newLocation = {
      lat: parseFloat(currentLat),
      lon: parseFloat(currentLon),
      radius: parseFloat(currentRadius),
      name: locationName
    };
    
    setLocations([...locations, newLocation]);
    setLocationName('');
  };

  const removeLocation = (index: number) => {
    setLocations(locations.filter((_, i) => i !== index));
  };

  const toggleWiFi = (ssid: string) => {
    setSelectedWiFi(prev => 
      prev.includes(ssid) 
        ? prev.filter(s => s !== ssid)
        : [...prev, ssid]
    );
  };

  const handleSetup = async () => {
    try {
      if (locations.length === 0) {
        alert('Please add at least one location');
        return;
      }
      
      const locationData = locations.map(l => [l.lat, l.lon, l.radius]);
      
      await invoke('setup_geofence', {
        locations: locationData,
        wifiSsids: selectedWiFi
      });

      // Start monitoring with selected sensitive files
      await invoke('start_geofence_monitoring', {
        sensitiveFiles, // Lock only chosen sensitive files
        userId
      });

      setIsMonitoring(true);
      
      console.log('Geofence monitoring started - will lock sensitive files when outside safe zones');
    } catch (err) {
      alert(`❌ Setup failed: ${err}`);
    }
  };

  const handleLockSensitiveFiles = async () => {
    try {
      if (sensitiveFiles.length === 0) {
        alert('Please add sensitive files first in the Sensitive Files section');
        return;
      }
      // Lock specific sensitive files
      const manager = await import('@tauri-apps/api/core');
      await manager.invoke('start_geofence_monitoring', {
        sensitiveFiles,
        userId
      });
      // Force immediate lock
      for (const filePath of sensitiveFiles) {
        await manager.invoke('lock_files', { filePaths: [filePath], userId });
      }
      alert('🔒 Sensitive files have been locked!');
    } catch (err) {
      alert(`❌ Lock failed: ${err}`);
    }
  };

  const handleStop = async () => {
    try {
      await invoke('stop_geofence_monitoring');
      setIsMonitoring(false);
      alert('🛑 Geofence monitoring stopped');
    } catch (err) {
      alert(`❌ Stop failed: ${err}`);
    }
  };

  const handleUnlock = async () => {
    try {
      await invoke('unlock_with_pin', {
        userId,
        pin: unlockPin,
        filePaths: sensitiveFiles
      });
      
      setUnlockPin('');
      setShowUnlock(false);
      await checkStatus();
      alert('🔓 Files unlocked successfully!');
    } catch (err) {
      alert(`❌ Unlock failed: ${err}`);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h2>🗺️ Geofenced Lock Setup</h2>
        
        {showUnlock && (
          <div className="unlock-section" style={{ background: '#ffe6e6', padding: '15px', marginBottom: '20px', borderRadius: '8px' }}>
            <h3>🔒 Files are currently LOCKED</h3>
            <p>Enter your PIN to unlock sensitive files:</p>
            <input
              type="password"
              placeholder="Enter PIN"
              value={unlockPin}
              onChange={(e) => setUnlockPin(e.target.value)}
              style={{ marginRight: '10px' }}
            />
            <button onClick={handleUnlock} className="btn-primary">Unlock Files</button>
          </div>
        )}

        <div className="form-group">
          <label>Add Safe Location:</label>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '10px' }}>
            <input
              type="number"
              step="any"
              placeholder="Latitude"
              value={currentLat}
              onChange={(e) => setCurrentLat(e.target.value)}
            />
            <input
              type="number"
              step="any"
              placeholder="Longitude"
              value={currentLon}
              onChange={(e) => setCurrentLon(e.target.value)}
            />
          </div>
          <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
            <input
              type="text"
              placeholder="Location Name (e.g., Home, Office)"
              value={locationName}
              onChange={(e) => setLocationName(e.target.value)}
              style={{ flex: 1 }}
            />
            <input
              type="number"
              placeholder="Radius (m)"
              value={currentRadius}
              onChange={(e) => setCurrentRadius(e.target.value)}
              style={{ width: '100px' }}
            />
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button onClick={getCurrentLocation} className="btn-secondary">📍 Use Current</button>
            <button onClick={addLocation} className="btn-primary">➕ Add Location</button>
          </div>
        </div>

        {locations.length > 0 && (
          <div className="form-group">
            <label>Safe Locations ({locations.length}):</label>
            <div style={{ maxHeight: '150px', overflowY: 'auto', border: '1px solid #333', borderRadius: '5px', padding: '10px' }}>
              {locations.map((loc, index) => (
                <div key={index} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '5px 0', borderBottom: '1px solid #444' }}>
                  <span>{loc.name} ({loc.lat.toFixed(4)}, {loc.lon.toFixed(4)}) - {loc.radius}m</span>
                  <button onClick={() => removeLocation(index)} style={{ background: '#ff4444', color: 'white', border: 'none', borderRadius: '3px', padding: '2px 8px' }}>✕</button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="form-group">
          <label>Available Wi-Fi Networks:</label>
          <button onClick={scanWiFi} className="btn-secondary" style={{ marginBottom: '10px' }}>🔄 Refresh Networks</button>
          <div className="wifi-list">
            {availableWiFi.map((ssid, index) => (
              <label key={index} className="wifi-item">
                <input
                  type="checkbox"
                  checked={selectedWiFi.includes(ssid)}
                  onChange={() => toggleWiFi(ssid)}
                />
                <span className="wifi-name">📶 {ssid}</span>
              </label>
            ))}
          </div>
          <p style={{ fontSize: '0.9rem', color: '#888', marginTop: '5px' }}>Selected: {selectedWiFi.length} networks</p>
        </div>

        {status && (
          <div className="status-display" style={{ background: '#f0f0f0', padding: '10px', margin: '15px 0', borderRadius: '5px' }}>
            <h4>Current Status:</h4>
            <p>📍 Inside Geofence: {status.inside_geofence ? '✅ Yes' : '❌ No'}</p>
            <p>🔒 Files Locked: {status.files_locked ? '🔒 Yes' : '🔓 No'}</p>
            <p>🕒 Last Check: {new Date(status.last_check).toLocaleString()}</p>
          </div>
        )}

        <div className="modal-actions">
          {!isMonitoring ? (
            <>
              <button onClick={handleSetup} className="btn-primary">
                🚀 Start Auto-Lock
              </button>
              <button onClick={handleLockSensitiveFiles} className="btn-danger">
                🔒 Lock Sensitive Files Now
              </button>
            </>
          ) : (
            <button onClick={handleStop} className="btn-danger">
              🛑 Stop Monitoring
            </button>
          )}
          <button onClick={onClose} className="btn-secondary">Close</button>
        </div>

        <div className="info-box" style={{ marginTop: '15px', padding: '10px', background: '#e6f3ff', borderRadius: '5px' }}>
          <h4>ℹ️ How it works:</h4>
          <ul style={{ margin: 0, paddingLeft: '20px' }}>
            <li>🔒 ONLY SENSITIVE FILES you chose will be locked</li>
            <li>📁 Locks files/folders from Sensitive Files section</li>
            <li>🏠 Multiple safe locations (Home, Office, etc.)</li>
            <li>🔐 BOTH Wi-Fi AND GPS must match to unlock</li>
            <li>⚠️ Files lock if either Wi-Fi OR GPS fails</li>
            <li>🛡️ Files stay locked if location services disabled</li>
            <li>🔑 Only your PIN unlocks files</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default GeofenceModal;