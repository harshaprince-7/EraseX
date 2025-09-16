import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface SensitiveFilesProps {
  sensitiveFiles: string[];
  setSensitiveFiles: (files: string[]) => void;
  filesLocked: boolean;
  setFilesLocked: (locked: boolean) => void;
  setPinAttempts: (attempts: number) => void;
  currentUserId: number;
  theme: string;
}

const SensitiveFiles: React.FC<SensitiveFilesProps> = ({
  sensitiveFiles,
  setSensitiveFiles,
  filesLocked,
  setFilesLocked,
  setPinAttempts,
  currentUserId,
  theme
}) => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedPath, setSelectedPath] = useState('');

  const handleAddFile = async () => {
    try {
      const filePath = await invoke<string>('select_file');
      if (filePath && !sensitiveFiles.includes(filePath)) {
        setSensitiveFiles([...sensitiveFiles, filePath]);
      }
    } catch (err) {
      console.error('Failed to select file:', err);
    }
  };

  const handleAddFolder = async () => {
    try {
      const folderPath = await invoke<string>('select_folder');
      if (folderPath && !sensitiveFiles.includes(folderPath)) {
        setSensitiveFiles([...sensitiveFiles, folderPath]);
      }
    } catch (err) {
      console.error('Failed to select folder:', err);
    }
  };

  const handleRemove = (index: number) => {
    setSensitiveFiles(sensitiveFiles.filter((_, i) => i !== index));
  };

  const handleLockFiles = async () => {
    try {
      if (sensitiveFiles.length === 0) {
        alert('Please add files or folders first');
        return;
      }
      
      await invoke('lock_sensitive_files', {
        filePaths: sensitiveFiles,
        userId: currentUserId
      });
      
      setFilesLocked(true);
      alert('🔒 Sensitive files/folders have been locked!');
    } catch (err) {
      alert(`❌ Lock failed: ${err}`);
    }
  };

  return (
    <div className="card">
      <h2>🔒 Sensitive Files & Folders</h2>
      
      <div className="sensitive-files-actions">
        <button onClick={handleAddFile} className="btn-primary">
          📄 Add File
        </button>
        <button onClick={handleAddFolder} className="btn-primary">
          📁 Add Folder
        </button>
        <button onClick={handleLockFiles} className="btn-danger">
          🔒 Lock All Now
        </button>
      </div>

      {sensitiveFiles.length > 0 ? (
        <div className="sensitive-files-list">
          <h3>Protected Items ({sensitiveFiles.length})</h3>
          {sensitiveFiles.map((filePath, index) => (
            <div key={index} className="sensitive-file-item">
              <span className="file-icon">
                {filePath.includes('.') && !filePath.endsWith('\\') && !filePath.endsWith('/') ? '📄' : '📁'}
              </span>
              <div className="file-details">
                <span className="file-name" title={filePath}>
                  {filePath.split(/[\\\/]/).pop() || filePath}
                </span>
                <span className="file-type">
                  {filePath.includes('.') && !filePath.endsWith('\\') && !filePath.endsWith('/') ? 'File' : 'Folder'}
                </span>
                <span className="file-path-small" title={filePath}>
                  {filePath.length > 80 ? `...${filePath.slice(-80)}` : filePath}
                </span>
              </div>
              <button 
                onClick={() => handleRemove(index)}
                className="remove-btn"
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-state">
          <p>No sensitive files or folders added yet.</p>
          <p>Click "Add File" or "Add Folder" to protect your important data.</p>
        </div>
      )}

      {filesLocked && (
        <div className="lock-status">
          <p>🔒 Files are currently LOCKED</p>
          <p>Use geofence PIN unlock or be in a safe location to unlock.</p>
        </div>
      )}

      {/* Simple List - Show Selected Items */}
      {sensitiveFiles.length > 0 && (
        <div className="simple-list-section">
          <h3>Protected Items ({sensitiveFiles.length})</h3>
          <div className="simple-list">
            {sensitiveFiles.map((filePath, index) => {
              const isFolder = !filePath.includes('.') || filePath.endsWith('\\') || filePath.endsWith('/');
              const name = filePath.split(/[\\\/]/).pop() || filePath;
              return (
                <div key={index} className="simple-item">
                  <span className="simple-icon">{isFolder ? '📁' : '📄'}</span>
                  <span className="simple-name">{name}</span>
                  <button 
                    onClick={() => handleRemove(index)}
                    className="simple-remove-btn"
                  >
                    ✕
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="info-box" style={{color: 'black'}}>
        <h4 style={{color: 'black'}}>ℹ️ How it works:</h4>
        <ul style={{color: 'black'}}>
          <li>📄 Add individual files you want to protect</li>
          <li>📁 Add entire folders (all contents will be protected)</li>
          <li>🗺️ Use Geofenced Lock to auto-lock when outside safe zones</li>
          <li>🔑 Only your PIN can unlock protected items</li>
          <li>⚠️ Files auto-lock after 3 wrong PIN attempts during wipe operations</li>
        </ul>
      </div>
    </div>
  );
};

export default SensitiveFiles;