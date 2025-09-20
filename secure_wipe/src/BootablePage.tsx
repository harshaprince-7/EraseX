import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface BootablePageProps {}

const BootablePage: React.FC<BootablePageProps> = () => {
  const [usbDrives, setUsbDrives] = useState<string[]>([]);
  const [selectedDrive, setSelectedDrive] = useState<string>('');
  const [wipeMode, setWipeMode] = useState<string>('Quick');
  const [isCreating, setIsCreating] = useState<boolean>(false);
  const [progress, setProgress] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');

  useEffect(() => {
    loadUsbDrives();
  }, []);

  const loadUsbDrives = async () => {
    try {
      const drives = await invoke<string[]>('list_usb_drives');
      setUsbDrives(drives);
    } catch (err) {
      setError(`Failed to load USB drives: ${err}`);
    }
  };

  const createBootableUSB = async () => {
    if (!selectedDrive) {
      setError('Please select a USB drive');
      return;
    }

    setIsCreating(true);
    setError('');
    setSuccess('');
    setProgress('Starting bootable USB creation...');

    try {
      // Extract drive number from selection (format: "0 - Model (Size)")
      const driveNumber = selectedDrive.split(' - ')[0];
      
      setProgress('Downloading Alpine Linux and bootloader files...');
      const result = await invoke<string>('create_bootable_usb', {
        usbDrive: driveNumber,
        wipeMode: wipeMode
      });
      
      setSuccess(result);
      setProgress('');
    } catch (err) {
      setError(`Failed to create bootable USB: ${err}`);
      setProgress('');
    } finally {
      setIsCreating(false);
    }
  };

  const createBootableISO = async () => {
    setIsCreating(true);
    setError('');
    setSuccess('');
    setProgress('Creating bootable ISO...');

    try {
      setProgress('Downloading Alpine Linux and building ISO...');
      const result = await invoke<string>('create_iso_from_usb', {
        wipeMode: wipeMode,
        outputPath: ''
      });
      
      setSuccess(result);
      setProgress('');
    } catch (err) {
      setError(`Failed to create ISO: ${err}`);
      setProgress('');
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="bootable-page">
      <div className="card">
        <h2>🔥 Bootable USB/ISO Creator</h2>
        <p>Create bootable media for secure wiping without operating system</p>

        {/* Wipe Mode Selection */}
        <div className="section">
          <h3>Select Wipe Method</h3>
          <div className="wipe-modes">
            {['Quick', 'DoD', 'Gutmann'].map((mode) => (
              <div
                key={mode}
                className={`wipe-option ${wipeMode === mode ? 'selected' : ''}`}
                onClick={() => setWipeMode(mode)}
              >
                <strong>{mode}</strong>
                <br />
                <span>
                  {mode === 'Quick' && 'Fast wipe (first + last 1GB)'}
                  {mode === 'DoD' && 'DoD 5220.22-M (3 passes)'}
                  {mode === 'Gutmann' && 'Gutmann method (35 passes)'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* USB Drive Selection */}
        <div className="section">
          <h3>Create Bootable USB</h3>
          <div className="usb-selection">
            <label>Select USB Drive:</label>
            <select 
              value={selectedDrive} 
              onChange={(e) => setSelectedDrive(e.target.value)}
              disabled={isCreating}
            >
              <option value="">-- Select USB Drive --</option>
              {usbDrives.map((drive, index) => (
                <option key={index} value={drive}>
                  {drive}
                </option>
              ))}
            </select>
            <button 
              onClick={loadUsbDrives} 
              disabled={isCreating}
              className="refresh-btn"
            >
              🔄 Refresh
            </button>
          </div>
          
          <div className="warning-box">
            <strong>⚠️ WARNING:</strong> This will completely erase the selected USB drive!
            All data on the USB will be permanently lost.
          </div>

          <button 
            onClick={createBootableUSB}
            disabled={isCreating || !selectedDrive}
            className="create-btn"
          >
            {isCreating ? 'Creating...' : '💿 Create Bootable USB'}
          </button>
        </div>

        {/* ISO Creation */}
        <div className="section">
          <h3>Create Bootable ISO</h3>
          <p>Create an ISO file that can be burned to DVD or used with virtual machines</p>
          
          <button 
            onClick={createBootableISO}
            disabled={isCreating}
            className="create-btn"
          >
            {isCreating ? 'Creating...' : '💽 Create Bootable ISO'}
          </button>
        </div>

        {/* Progress Display */}
        {progress && (
          <div className="progress-box">
            <div className="spinner"></div>
            <span>{progress}</span>
          </div>
        )}

        {/* Error Display */}
        {error && (
          <div className="error-box">
            <strong>❌ Error:</strong> {error}
            <button onClick={() => setError('')} className="close-btn">×</button>
          </div>
        )}

        {/* Success Display */}
        {success && (
          <div className="success-box">
            <div style={{ whiteSpace: 'pre-line' }}>{success}</div>
            <button onClick={() => setSuccess('')} className="close-btn">×</button>
          </div>
        )}

        {/* Instructions */}
        <div className="instructions">
          <h3>📋 Instructions</h3>
          <div className="instruction-tabs">
            <div className="tab-content">
              <h4>Bootable USB Usage:</h4>
              <ol>
                <li>Insert the created USB into target computer</li>
                <li>Boot from USB (F12/F2/DEL during startup)</li>
                <li>Select "Secure Wipe - {wipeMode} (Automatic)"</li>
                <li>Type "DESTROY" to confirm wipe operation</li>
                <li>Wait for completion and certificate generation</li>
              </ol>
              
              <h4>Bootable ISO Usage:</h4>
              <ol>
                <li>Burn ISO to DVD or use with VM software</li>
                <li>Boot from DVD/ISO</li>
                <li>Follow same steps as USB</li>
              </ol>

              <h4>Features:</h4>
              <ul>
                <li>✅ Works on any PC (UEFI + BIOS support)</li>
                <li>✅ Alpine Linux 3.18 base system</li>
                <li>✅ Hardware driver support included</li>
                <li>✅ Automatic certificate generation</li>
                <li>✅ Network connectivity for certificate upload</li>
                <li>✅ Multiple wipe methods available</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      <style jsx>{`
        .bootable-page {
          padding: 20px;
          max-width: 1000px;
          margin: 0 auto;
        }

        .card {
          background: white;
          border-radius: 12px;
          padding: 30px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .section {
          margin: 30px 0;
          padding: 20px;
          border: 1px solid #e0e0e0;
          border-radius: 8px;
        }

        .wipe-modes {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 15px;
          margin: 15px 0;
        }

        .wipe-option {
          padding: 15px;
          border: 2px solid #ddd;
          border-radius: 8px;
          cursor: pointer;
          text-align: center;
          transition: all 0.3s ease;
        }

        .wipe-option:hover {
          border-color: #007bff;
          background-color: #f8f9fa;
        }

        .wipe-option.selected {
          border-color: #007bff;
          background-color: #e3f2fd;
        }

        .usb-selection {
          display: flex;
          gap: 10px;
          align-items: center;
          margin: 15px 0;
          flex-wrap: wrap;
        }

        .usb-selection select {
          flex: 1;
          min-width: 200px;
          padding: 10px;
          border: 1px solid #ddd;
          border-radius: 4px;
        }

        .refresh-btn {
          padding: 10px 15px;
          background: #6c757d;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }

        .refresh-btn:hover {
          background: #5a6268;
        }

        .create-btn {
          padding: 15px 30px;
          background: #007bff;
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 16px;
          font-weight: bold;
          cursor: pointer;
          margin: 15px 0;
          transition: background 0.3s ease;
        }

        .create-btn:hover:not(:disabled) {
          background: #0056b3;
        }

        .create-btn:disabled {
          background: #6c757d;
          cursor: not-allowed;
        }

        .warning-box {
          background: #fff3cd;
          border: 1px solid #ffeaa7;
          color: #856404;
          padding: 15px;
          border-radius: 8px;
          margin: 15px 0;
        }

        .progress-box {
          background: #d1ecf1;
          border: 1px solid #bee5eb;
          color: #0c5460;
          padding: 15px;
          border-radius: 8px;
          margin: 15px 0;
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .spinner {
          width: 20px;
          height: 20px;
          border: 2px solid #f3f3f3;
          border-top: 2px solid #007bff;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        .error-box {
          background: #f8d7da;
          border: 1px solid #f5c6cb;
          color: #721c24;
          padding: 15px;
          border-radius: 8px;
          margin: 15px 0;
          position: relative;
        }

        .success-box {
          background: #d4edda;
          border: 1px solid #c3e6cb;
          color: #155724;
          padding: 15px;
          border-radius: 8px;
          margin: 15px 0;
          position: relative;
        }

        .close-btn {
          position: absolute;
          top: 10px;
          right: 15px;
          background: none;
          border: none;
          font-size: 20px;
          cursor: pointer;
          color: inherit;
        }

        .instructions {
          margin-top: 30px;
          padding: 20px;
          background: #f8f9fa;
          border-radius: 8px;
        }

        .instructions h4 {
          color: #007bff;
          margin-top: 20px;
        }

        .instructions ol, .instructions ul {
          margin: 10px 0;
          padding-left: 20px;
        }

        .instructions li {
          margin: 5px 0;
        }
      `}</style>
    </div>
  );
};

export default BootablePage;