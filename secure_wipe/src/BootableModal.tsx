import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface BootableModalProps {
  show: boolean;
  onClose: () => void;
}

const BootableModal: React.FC<BootableModalProps> = ({ show, onClose }) => {
  const [usbDrives, setUsbDrives] = useState<string[]>([]);
  const [selectedUsb, setSelectedUsb] = useState<string>("");
  const [isCreating, setIsCreating] = useState(false);

  useEffect(() => {
    if (show) {
      loadUsbDrives();
    }
  }, [show]);

  const loadUsbDrives = async () => {
    try {
      const drives = await invoke<string[]>("list_usb_drives");
      setUsbDrives(drives);
    } catch (err) {
      console.error("Failed to load USB drives:", err);
    }
  };

  const createBootableUsb = async () => {
    if (!selectedUsb) {
      alert("Please select a USB drive");
      return;
    }

    setIsCreating(true);
    try {
      // Build bootable environment
      await invoke("build_bootable_environment");
      
      // Create ISO
      await invoke("create_iso");
      
      // Create bootable USB
      await invoke("create_bootable_usb", {
        usbDrive: selectedUsb,
        isoPath: "secure_wipe_boot.iso"
      });
      
      alert("✅ Bootable USB created successfully!\n\nUsage:\n1. Insert USB into target computer\n2. Boot from USB (F12 during startup)\n3. Run secure wipe without OS");
      onClose();
    } catch (err) {
      alert(`❌ Error: ${err}`);
    } finally {
      setIsCreating(false);
    }
  };

  if (!show) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h3>Create Bootable USB</h3>
        
        <div className="form-group">
          <label>Select USB Drive:</label>
          <select 
            value={selectedUsb} 
            onChange={(e) => setSelectedUsb(e.target.value)}
          >
            <option value="">Choose USB Drive...</option>
            {usbDrives.map((drive, index) => (
              <option key={index} value={drive}>
                {drive}
              </option>
            ))}
          </select>
        </div>

        <div className="modal-actions">
          <button onClick={onClose} disabled={isCreating}>
            Cancel
          </button>
          <button 
            onClick={createBootableUsb} 
            disabled={isCreating || !selectedUsb}
          >
            {isCreating ? "Creating..." : "Create Bootable USB"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default BootableModal;