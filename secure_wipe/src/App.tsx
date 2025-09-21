import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { User, MoreVertical, Sun, Moon, Shield, Lock } from "lucide-react";
import "./App.css";
import "./error-banner.css";
import "./certificate-status.css";
import Register from "./Register";
import Login from "./Login";
import BootableModal from "./BootableModal";
import PxeBootModal from "./PxeBootModal";
import GeofenceModal from "./GeofenceModal";
import SensitiveFiles from "./SensitiveFiles";


interface Drive {
  name: string;
  selected: boolean;
}

interface Certificate {
  id: number;
  user_id: number;
  drive: string;
  wipe_mode: string;
  device_id: string;
  timestamp: string;
  content: string;
  status: string;
}

function App() {
  const [authState, setAuthState] = useState<
    "landing" | "register" | "login" | "authenticated"
  >("landing");
  const [drives, setDrives] = useState<Drive[]>([]);
  const [showConfirm, setShowConfirm] = useState(false);
  const [pin, setPin] = useState("");
  const [error, setError] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const theme = "rose-cream";
  const [showProfile, setShowProfile] = useState(false);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [errorMessage, setErrorMessage] = useState<string>("");
  const [selectedWipe, setSelectedWipe] = useState<string | null>(null);
  const [selectedRandomMethod, setSelectedRandomMethod] = useState<
    string | null
  >(null);
  const [privacyMode, setPrivacyMode] = useState(false);
  const [lastActivity, setLastActivity] = useState(Date.now());
  const [isAndroid, setIsAndroid] = useState(false);
  const [enableEncryption, setEnableEncryption] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [showCertTypeModal, setShowCertTypeModal] = useState(false);
  const [selectedCertType, setSelectedCertType] = useState<"audit" | "pdf" | null>(null);
  const [showRandomWipeModal, setShowRandomWipeModal] = useState(false);
  const [currentUserId, setCurrentUserId] = useState<number | null>(null);
  const [showPin, setShowPin] = useState(false);
  const [showPinPasswordModal, setShowPinPasswordModal] = useState(false);
  const [showPinDisplayModal, setShowPinDisplayModal] = useState(false);
  const [pinPassword, setPinPassword] = useState(""); // stores entered password
  const [pinPasswordError, setPinPasswordError] = useState("");
  const [showSecurityOptionsModal, setShowSecurityOptionsModal] = useState(false);
  const [showChangePasswordModal, setShowChangePasswordModal] = useState(false);
  const [showChangePinModal, setShowChangePinModal] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [sensitiveFiles, setSensitiveFiles] = useState<string[]>([]);
  const [showSensitiveFilesModal, setShowSensitiveFilesModal] = useState(false);
  const [pinAttempts, setPinAttempts] = useState(0);
  const [filesLocked, setFilesLocked] = useState(false); 
  // page navigation
  const [currentPage, setCurrentPage] = useState<
    "home" | "dashboard" | "certificates" | "sensitive-files" | "bootable"
  >("home");
  const [userPin, setUserPin] = useState<string | null>(null);
  const [showBootableModal, setShowBootableModal] = useState(false);
  const [usbDrives, setUsbDrives] = useState<string[]>([]);
  const [selectedUsb, setSelectedUsb] = useState<string>("");
  const [showHelpModal, setShowHelpModal] = useState(false);
  const [showPxeBootModal, setShowPxeBootModal] = useState(false);
  const [showGeofenceModal, setShowGeofenceModal] = useState(false);
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [unlockPin, setUnlockPin] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [isSsdDetected, setIsSsdDetected] = useState(false);
  const [showProgressModal, setShowProgressModal] = useState(false);
  const [progressMinimized, setProgressMinimized] = useState(false);
  const [wipeProgress, setWipeProgress] = useState({ pass: 1, totalPasses: 7, progress: 0, bytesWritten: 0, totalBytes: 1 });
  const [showCancelConfirm, setShowCancelConfirm] = useState(false);
  const [cancelPin, setCancelPin] = useState("");
  const [cancelError, setCancelError] = useState("");

  // Enhanced drive type detection
  const [driveTypes, setDriveTypes] = useState<{[key: string]: string}>({});
  
  // Check if any selected drive is SSD
  const isSelectedDriveSsd = () => {
    const selectedDrives = drives.filter(d => d.selected);
    if (selectedDrives.length === 0) return false;
    
    return selectedDrives.some(drive => {
      const driveType = driveTypes[drive.name] || "";
      // Check for SSD, NVMe, or if it's F: drive (ESD-USB)
      return driveType.includes("SSD") || driveType.includes("NVMe") || drive.name.startsWith("F:");
    });
  };
  
  // Get drive type display text
  const getDriveTypeDisplay = (driveName: string) => {
    const driveType = driveTypes[driveName];
    if (!driveType) return "";
    
    if (driveType.includes("NVMe")) return " (NVMe SSD)";
    if (driveType.includes("USB SSD")) return " (USB SSD)";
    if (driveType.includes("SATA SSD")) return " (SATA SSD)";
    if (driveType.includes("HDD")) return " (HDD)";
    return "";
  };


  const toggleProfile = () => setShowProfile(!showProfile);
  const closeProfile = () => setShowProfile(false);

  useEffect(() => {
    const validateToken = async () => {
      const token = sessionStorage.getItem("authToken");
      if (token) {
        try {
          const user = await invoke<any>("verify_token", { token });
          setUsername(user.username);
          setEmail(user.email);
          setCurrentUserId(user.id);
          setAuthState("authenticated");
        } catch (err) {
          sessionStorage.removeItem("authToken");
          setAuthState("login");
        }
      }
    };
    
    // Detect Android platform
    const checkAndroid = async () => {
      try {
        await invoke("secure_wipe_android", { filePaths: [], wipeMode: "test" });
        setIsAndroid(true);
      } catch {
        setIsAndroid(false);
      }
    };
    
    validateToken();
    checkAndroid();
  }, []);

  useEffect(() => {
    if (authState === "authenticated") {
      const refreshInterval = setInterval(async () => {
        const token = sessionStorage.getItem("authToken");
        if (token) {
          try {
            const newToken = await invoke<string>("refresh_token", { token });
            sessionStorage.setItem("authToken", newToken);
          } catch (err) {
            handleLogout();
          }
        }
      }, 23 * 60 * 60 * 1000);

      return () => clearInterval(refreshInterval);
    }
  }, [authState]);

  // Auto-logout when privacy mode is enabled
  useEffect(() => {
    if (privacyMode && authState === "authenticated") {
      const checkInactivity = () => {
        const now = Date.now();
        if (now - lastActivity > 5 * 60 * 1000) { // 5 minutes
          alert("🔒 Auto-logout due to inactivity (Privacy Mode)");
          handleLogout();
        }
      };

      const inactivityTimer = setInterval(checkInactivity, 30000); // Check every 30 seconds
      return () => clearInterval(inactivityTimer);
    }
  }, [privacyMode, lastActivity, authState]);

  // Track user activity
  useEffect(() => {
    if (privacyMode) {
      const updateActivity = () => setLastActivity(Date.now());
      
      window.addEventListener('mousedown', updateActivity);
      window.addEventListener('keydown', updateActivity);
      window.addEventListener('scroll', updateActivity);
      
      return () => {
        window.removeEventListener('mousedown', updateActivity);
        window.removeEventListener('keydown', updateActivity);
        window.removeEventListener('scroll', updateActivity);
      };
    }
  }, [privacyMode]);

  useEffect(() => {
    if (authState === "authenticated") {
      const fetchDrives = async () => {
        try {
          const driveList = await invoke<string[]>("get_available_drives");
          setDrives(driveList.map((d: string) => ({ name: d, selected: false })));
          
          // Detect drive types for each drive
          const types: {[key: string]: string} = {};
          for (const drive of driveList) {
            try {
              const driveType = await invoke<string>("detect_drive_info", {
                selectedUsb: drive.replace(":", "")
              });
              types[drive] = driveType;
            } catch (err) {
              types[drive] = "Unknown";
            }
          }
          setDriveTypes(types);
          
          // Check for SSD support
          try {
            const ssdSupport = await invoke<string>("check_ssd_support");
            setIsSsdDetected(ssdSupport.includes("available") || ssdSupport.includes("supported"));
          } catch (err) {
            setIsSsdDetected(false);
          }
        } catch (err) {
          console.error("Error fetching drives:", err);
        }
      };
      fetchDrives();
      
      // Listen for wipe progress events
      const unlisten = listen('wipe-progress', (event: any) => {
        console.log('Progress event received:', event.payload);
        const payload = event.payload;
        console.log('Setting progress:', payload);
        setWipeProgress({
          pass: payload.pass || 1,
          totalPasses: payload.total_passes || 7,
          progress: payload.progress || 0,
          bytesWritten: payload.bytes_written || 0,
          totalBytes: payload.total_bytes || 1
        });
      });
      
      // Listen for wipe completion events
      const unlistenComplete = listen('wipe-completed', () => {
        console.log('Wipe completed event received');
        setShowProgressModal(false);
      });
      
      return () => {
        unlisten.then(fn => fn());
        unlistenComplete.then(fn => fn());
      };
    }
  }, [authState]);

  // Registration
  const handleRegisterSuccess = (token: string, user: any, pin: string) => {
    sessionStorage.setItem("authToken", token);
    setUsername(user.username);
    setEmail(user.email);
    setCurrentUserId(user.id);
    setUserPin(pin);
    alert(`🎉 Your PIN: ${pin}`);
    setAuthState("authenticated");
  };

  // Login
  const handleLoginSuccess = async (token: string, user: any, pin: string) => {
    sessionStorage.setItem("authToken", token);
    setUsername(user.username);
    setEmail(user.email);
    setCurrentUserId(user.id);
    setUserPin(pin);
    setAuthState("authenticated");
  };

  const handleLogout = () => {
    sessionStorage.removeItem("authToken");
    setAuthState("login");
    setShowProfile(false);
  };

  const toggleDrive = (index: number) => {
    const newDrives = [...drives];
    newDrives[index].selected = !newDrives[index].selected;
    setDrives(newDrives);
    
    // Reset wipe method when drive selection changes
    setSelectedWipe(null);
    setSelectedRandomMethod(null);
  };

  const handleDelete = () => {
    const selected = drives.filter((d) => d.selected).map((d) => d.name);
    if (selected.length === 0) {
      alert("Please select at least one drive to wipe!");
      return;
    }
    if (!selectedWipe) {
      alert("⚠️ Please select a wipe mode!");
      return;
    }
    if (selectedWipe === "Purge" && !selectedRandomMethod) {
      setShowRandomWipeModal(true);
      return;
    }
    setShowConfirm(true);
  };

  const confirmDelete = async () => {
    const selected = drives.filter((d) => d.selected).map((d) => d.name);
    try {
      const isValid = await invoke<boolean>("verify_user_pin", {
        userId: currentUserId,
        pin: pin,
      });
      if (!isValid) {
        const newAttempts = pinAttempts + 1;
        setPinAttempts(newAttempts);
        
        if (newAttempts >= 3) {
          // Lock sensitive files after 3 failed attempts
          if (sensitiveFiles.length > 0) {
            await invoke("lock_sensitive_files", {
              filePaths: sensitiveFiles,
              userId: currentUserId
            });
            setFilesLocked(true);
            setPinAttempts(0);
            alert("🔒 Sensitive files have been locked due to multiple failed PIN attempts!");
          }
        }
        
        setError(`❌ Incorrect PIN. Try again. (${newAttempts}/3 attempts)`);
        return;
      }

      // Reset attempts on successful PIN
      setPinAttempts(0);

      // Close modal immediately after successful PIN verification
      setShowConfirm(false);
      setPin("");
      setError("");

      // Reset cancellation flag before starting wipe
      try {
        await invoke("reset_wipe_cancelled");
      } catch (err) {
        console.error("Failed to reset cancellation flag:", err);
      }
      
      // Show progress modal for USB drives
      const isUsbDrive = selected.some(drive => {
        const driveType = driveTypes[drive] || "";
        return driveType.includes("USB SSD") || drive.startsWith("F:");
      });
      
      if (isUsbDrive && (selectedWipe === "Destroy" || selectedWipe === "Purge")) {
        setShowProgressModal(true);
        setWipeProgress({ pass: 1, totalPasses: selectedWipe === "Destroy" ? 7 : 1, progress: 0, bytesWritten: 0, totalBytes: 0 });
      }

      // Perform wipe operation on selected drives
      let allWipesSuccessful = true;
      let wipeErrors = [];
      
      for (const drive of selected) {
        try {
          let wipeResult;
          if (selectedWipe === "Clear") {
            wipeResult = await invoke("clear_drive_data", {
              selectedUsb: drive.replace(":", ""),
            });
          } else if (selectedWipe === "Destroy") {
            const driveType = driveTypes[drive] || "";
            if (driveType.includes("USB SSD") || drive.startsWith("F:")) {
              wipeResult = await invoke("overwrite_usb_files_with_progress", {
                driveLetter: drive,
                passes: 7
              });
            } else {
              wipeResult = await invoke("hybrid_crypto_erase", {
                selectedUsb: drive.replace(":", ""),
              });
            }
          } else {
            wipeResult = await invoke("replace_random_byte", {
              method: selectedWipe === "Purge" ? selectedRandomMethod : selectedWipe,
              selectedUsb: drive.replace(":", ""),
            });
          }
          setErrorMessage(`✅ ${wipeResult}`);
        } catch (wipeErr) {
          allWipesSuccessful = false;
          const sanitizedError = String(wipeErr).replace(/<[^>]*>/g, '');
          wipeErrors.push(`${drive}: ${sanitizedError}`);
          setErrorMessage(`❌ Operation failed for ${drive}: ${sanitizedError}`);
        }
      }
      
      // Close progress modal
      setShowProgressModal(false);

      // Generate certificates only if all wipes were successful
      if (allWipesSuccessful) {
        try {
          // Generate open audit certificate
          const auditCert = await invoke("generate_audit_certificate", {
            drive: selected.join(", "),
            wipeMode: selectedWipe === "Purge" ? selectedRandomMethod : selectedWipe,
            user: username,
            complianceStandard: "NIST 800-88, DoD 5220.22-M",
            userId: currentUserId,
            status: "completed",
          });
          
          // Generate regular certificate for database
          await invoke("generate_certificate", {
            userId: currentUserId,
            drive: selected.join(", "),
            wipeMode: selectedWipe === "Purge" ? selectedRandomMethod : selectedWipe,
            user: username,
            status: "completed"
          });
          
          // Save audit certificate
          const blob = new Blob([auditCert], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          const filename = `audit_certificate_${Date.now()}.json`;
          a.href = url;
          a.download = filename;
          a.click();
          URL.revokeObjectURL(url);
          
          // Make the downloaded file read-only after a short delay
          setTimeout(async () => {
            try {
              const downloadsPath = await invoke<string>("select_folder");
              const filePath = `${downloadsPath}\\${filename}`;
              await invoke("make_audit_certificate_readonly", { filePath });
            } catch (err) {
              console.log("Could not make file read-only:", err);
            }
          }, 2000);

          setErrorMessage(`✅ Wiping completed successfully!`);
        } catch (certErr) {
          setErrorMessage(`⚠️ Wiping completed but certificate generation failed: ${certErr}`);
        }
      } else {
        // Generate incomplete certificate for failed operations
        try {
          await invoke("generate_certificate", {
            userId: currentUserId,
            drive: selected.join(", "),
            wipeMode: selectedWipe === "Purge" ? selectedRandomMethod : selectedWipe,
            user: username,
            status: `incomplete - ${wipeErrors.join('; ')}`
          });
        } catch (certErr) {
          console.error("Failed to generate incomplete certificate:", certErr);
        }
        setErrorMessage(`❌ Wiping failed for some drives: ${wipeErrors.join('; ')}`);
      }
    } catch (err) {
      alert(`❌ Error: ${err}`);
    }
  };

  if (authState === "landing") {
  return (
    <LandingPage
      onLogin={() => setAuthState("login")}
    />
  );
}
  // Show authentication pages if not authenticated
  if (authState === "register") {
    return (
      <Register
        onSuccess={handleRegisterSuccess}
        onSwitch={() => setAuthState("login")}
      />
    );
  }

  if (authState === "login") {
    return (
      <Login
        onSuccess={handleLoginSuccess}
        onSwitch={() => setAuthState("register")}
      />
    );
  }

  const handleVerifyCertificate = () => {
    setShowCertTypeModal(true);
  };
  
  const handleCertTypeSelection = (type: "audit" | "pdf") => {
    setSelectedCertType(type);
    setShowCertTypeModal(false);
    setShowUploadModal(true);
  };
  
  return (
    <main className={`app-layout theme-${theme}`}>
      {/* Top Bar */}
      <header className="topbar">
        <h1>Trace Zero {isAndroid && <span style={{fontSize: '0.7em', color: '#4facfe'}}>📱 Android</span>}</h1>
      </header>

      {/* Sidebar */}
      <aside className="sidebar">
        {/* Profile */}
        <div>
          <div className="profile-header" onClick={toggleProfile}>
            <User className="sidebar-icon" />
            <span className="sidebar-username">{username}</span>
          </div>

          {showProfile && (
            <div className="profile-dropdown">
              <div className="profile-info">
                <label>Username</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
                <br />
                <label>Email</label>
                <br />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />

                <br />
                <button className="logout-btn">Change email</button>
                <br />
                <button
                  className="logout-btn"
                  onClick={() => {
                    handleLogout();
                    closeProfile();
                  }}
                >
                  Logout
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="sidebar-divider"></div>

        {/* Menu */}
        <div>
          <h3>Menu</h3>
          <div
            className={`sidebar-item ${currentPage === "home" ? "active" : ""}`}
            onClick={() => setCurrentPage("home")}
          >
            <span className="sidebar-icon">🏠</span>
            <span>Wipe Methods</span>
          </div>

          <div
            className={`sidebar-item ${
              currentPage === "dashboard" ? "active" : ""
            }`}
            onClick={() => setCurrentPage("dashboard")}
          >
            <span className="sidebar-icon">📊</span>
            <span>Dashboard</span>
          </div>
          <div
            className={`sidebar-item ${
              currentPage === "certificates" ? "active" : ""
            }`}
            onClick={() => setCurrentPage("certificates")}
          >
            <span className="sidebar-icon">📜</span>
            <span>Certificates</span>
          </div>
          <div
            className="sidebar-item sidebar-important"
            onClick={handleVerifyCertificate}
          >
            <span className="sidebar-icon">✅</span>
            <span>Verify Certificate</span>
          </div>
          <div
            className={`sidebar-item ${
              currentPage === "sensitive-files" ? "active" : ""
            }`}
            onClick={() => setCurrentPage("sensitive-files")}
          >
            <span className="sidebar-icon">🔒</span>
            <span>Sensitive Files</span>
          </div>
          
          <div
            className={`sidebar-item ${
              currentPage === "bootable" ? "active" : ""
            }`}
            onClick={() => setCurrentPage("bootable")}
          >
            <span className="sidebar-icon">💿</span>
            <span>Bootable USB/ISO</span>
          </div>
          
          <div
            className="sidebar-item"
            onClick={() => setShowPxeBootModal(true)}
          >
            <span className="sidebar-icon">🌐</span>
            <span>PXE Network Boot</span>
          </div>
          
          <div
            className="sidebar-item"
            onClick={() => setShowGeofenceModal(true)}
          >
            <span className="sidebar-icon">🗺️</span>
            <span>Geofenced Lock</span>
          </div>
          


          <div className="sidebar-item" onClick={() => setShowSettings(true)}>
            <MoreVertical className="sidebar-icon" />
            <span>Settings</span>
          </div>
        </div>
      </aside>

      {/* Error Message Display */}
      {errorMessage && (
        <div className={`error-banner ${errorMessage.includes('✅') ? 'success' : 'error'}`}>
          <span>{errorMessage}</span>
          <button onClick={() => setErrorMessage('')}>×</button>
        </div>
      )}

      {/* Main Content */}
      <section className="content">
        {currentPage === "home" && (
          <div className="card">
            <h2>Select a Disk</h2>
            <div className="drive-list">
              {drives.map((drive, index) => (
                <div
                  key={drive.name}
                  className={`drive-option ${
                    drive.selected ? "selected" : ""
                  }`}
                  onClick={() => toggleDrive(index)}
                >
                  {drive.name}{getDriveTypeDisplay(drive.name)}
                </div>
              ))}
            </div>

            <h3>Wipe Mode</h3>
            <div className="wipe-modes">
              <div
                className={`wipe-option ${
                  selectedWipe === "Clear" ? "selected" : ""
                } ${isSelectedDriveSsd() ? "disabled" : ""}`}
                onClick={() => !isSelectedDriveSsd() && setSelectedWipe("Clear")}
              >
                <strong>Clear</strong>
                <br />
                <span>
                  {isSelectedDriveSsd() 
                    ? "Not available for SSD" 
                    : "Quick removal (Recoverable)"}
                </span>
              </div>
              <div
                className={`wipe-option ${
                  selectedWipe === "Purge" ? "selected" : ""
                } ${isSelectedDriveSsd() ? "disabled" : ""}`}
                onClick={() => {
                  if (!isSelectedDriveSsd()) {
                    setSelectedWipe("Purge");
                    setShowRandomWipeModal(true);
                  }
                }}
              >
                <strong>Random Byte</strong>
                <br />
                <span>
                  {isSelectedDriveSsd() 
                    ? "Not available for SSD" 
                    : `Secure Wipe (hard to recover)${selectedRandomMethod ? ` — ${selectedRandomMethod}` : ""}`}
                </span>
              </div>
              <div
                className={`wipe-option ${
                  selectedWipe === "Destroy" ? "selected" : ""
                } ${!isSelectedDriveSsd() ? "disabled" : ""}`}
                onClick={() => isSelectedDriveSsd() && setSelectedWipe("Destroy")}
              >
                <strong>Destroy</strong>
                <br />
                <span>
                  {isSelectedDriveSsd() 
                    ? "Hybrid crypto-erase (NVMe instant, SATA secure erase)" 
                    : "SSD drive required"}
                </span>
              </div>
            </div>

            <button className="proceed-btn" onClick={handleDelete}>
              Proceed
            </button>
          </div>
        )}

        {currentPage === "dashboard" && (
          <Dashboard setCurrentPage={setCurrentPage} theme={theme} />
        )}

        {currentPage === "certificates" && currentUserId && (
          <Certificates userId={currentUserId} />
        )}

        {currentPage === "sensitive-files" && currentUserId && (
          <SensitiveFiles 
            sensitiveFiles={sensitiveFiles}
            setSensitiveFiles={setSensitiveFiles}
            filesLocked={filesLocked}
            setFilesLocked={setFilesLocked}
            setPinAttempts={setPinAttempts}
            currentUserId={currentUserId}
            theme={theme}
          />
        )}

        {currentPage === "bootable" && (
          <BootablePage />
        )}
      </section>

      {/* Footer */}
      <footer className="footer">
        <nav className="footer-links">
          <a href="#">About</a>
          <a href="#">Contact</a>
          <a href="#" onClick={() => setShowHelpModal(true)}>Help</a>
        </nav>
        <small>
          © {new Date().getFullYear()} Secure Wipe Utility. All rights reserved.
        </small>
      </footer>

      {/* PIN Modal */}
      {showConfirm && (
        <div className="modal">
          <div className="modal-content">
            <h2>Enter PIN to Confirm</h2>
            <input
              type="password"
              value={pin}
              onChange={(e) => setPin(e.target.value)}
              placeholder="Enter PIN"
            />
            {error && <p className="error">{error}</p>}
            <div className="modal-actions">
              <button onClick={confirmDelete}>Confirm</button>
              <button onClick={() => setShowConfirm(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Random Wipe Modal */}
      {showRandomWipeModal && (
        <div className="modal">
          <div className="modal-content">
            <h2>Select Random Wipe Method</h2>
            <div className="random-wipe-methods">
              {["Single Pass", "3 Pass DDOD", "7 Pass", "Gutmann"].map(
                (method) => (
                  <button
                    key={method}
                    className={
                      selectedRandomMethod === method ? "selected" : ""
                    }
                    onClick={() => {
                      setSelectedRandomMethod(method);
                      setShowRandomWipeModal(false);
                    }}
                  >
                    {method}
                  </button>
                )
              )}
            </div>
            <div className="modal-actions">
              <button onClick={() => setShowRandomWipeModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Settings Modal */}
      {showSettings && (
        <div className="modal">
          <div className="modal-content">
            <h2>Settings</h2>

            <div className="settings-section">
              <label>Privacy & Security</label>
              <div className="privacy-security-options">
                <div
                  className="privacy-option"
                  onClick={() => {
                    setPrivacyMode(!privacyMode);
                    setLastActivity(Date.now());
                  }}
                >
                  <Shield className="option-icon" />
                  <span>Privacy Mode (Auto-logout: 5min)</span>
                  <input type="checkbox" checked={privacyMode} readOnly />
                </div>
               <div className="privacy-option" onClick={() => setShowSecurityOptionsModal(true)}>
  <Lock className="option-icon" />
  <span>Security and password</span>
</div>
                <div
                  className="privacy-option"
                  onClick={() => {
                    if (filesLocked) {
                      setShowUnlockModal(true);
                    }
                  }}
                >
                  <Lock className="option-icon" />
                  <span>{filesLocked ? "Unlock Sensitive Files" : "Files Status: Unlocked"}</span>
                </div>


              </div>
            </div>
            <div className="modal-actions">
              <button className={`modal-close-btn theme-${theme}`} onClick={() => setShowSettings(false)}>Close</button>
            </div>
          </div>
        </div>
      )}
      {showPinPasswordModal && (
  <div className="modal">
    <div className="modal-content">
      <h2>Enter Password to Reveal PIN</h2>
      <input
        type="password"
        value={pinPassword}
        onChange={(e) => setPinPassword(e.target.value)}
        placeholder="Enter your password"
      />
      {pinPasswordError && <p className="error">{pinPasswordError}</p>}
      <div className="modal-actions">
        <button
          onClick={async () => {
            if (!pinPassword) return setPinPasswordError("Password is required");

            try {
              // Call backend to verify password
              const isValid = await invoke<boolean>("verify_user_password", {
                userId: currentUserId,
                password: pinPassword,
              });

              if (isValid) {
                setShowPinPasswordModal(false);
                setShowPinDisplayModal(true);
                setPinPassword("");
                setPinPasswordError("");
              } else {
                setPinPasswordError("❌ Incorrect password");
              }
            } catch (err) {
              setPinPasswordError(`⚠️ Error: ${err}`);
            }
          }}
        >
          Verify
        </button>
        <button
          onClick={() => {
            setShowPinPasswordModal(false);
            setPinPassword("");
            setPinPasswordError("");
          }}
        >
          Cancel
        </button>
      </div>
    </div>
  </div>
)}

      {/* Security Options Modal */}
      {showSecurityOptionsModal && (
        <div className="modal">
          <div className="modal-content">
            <h2>🔐 Security Options</h2>
            <div className="security-options">
              <button 
                className="security-option-btn"
                onClick={() => {
                  setShowSecurityOptionsModal(false);
                  setShowChangePasswordModal(true);
                }}
              >
                <span className="option-icon">🔑</span>
                Change Account Password
              </button>
              
              <button 
                className="security-option-btn"
                onClick={() => {
                  setShowSecurityOptionsModal(false);
                  setShowPinPasswordModal(true);
                }}
              >
                <span className="option-icon">👁️</span>
                View Confirmation PIN
              </button>
              
              <button 
                className="security-option-btn"
                onClick={() => {
                  setShowSecurityOptionsModal(false);
                  setShowChangePinModal(true);
                }}
              >
                <span className="option-icon">🔄</span>
                Change Confirmation PIN
              </button>
            </div>
            <div className="modal-actions">
              <button onClick={() => setShowSecurityOptionsModal(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Change Password Modal */}
      {showChangePasswordModal && (
        <div className="modal">
          <div className="modal-content">
            <h2>Change Account Password</h2>
            <input
              type="password"
              value={pinPassword}
              onChange={(e) => setPinPassword(e.target.value)}
              placeholder="Enter current password"
            />
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Enter new password"
            />
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm new password"
            />
            {passwordError && <p className="error">{passwordError}</p>}
            <div className="modal-actions">
              <button
                onClick={async () => {
                  if (!pinPassword || !newPassword || !confirmPassword) {
                    setPasswordError("All fields are required");
                    return;
                  }
                  if (newPassword !== confirmPassword) {
                    setPasswordError("New passwords don't match");
                    return;
                  }
                  try {
                    await invoke("change_user_password", {
                      userId: currentUserId,
                      currentPassword: pinPassword,
                      newPassword: newPassword
                    });
                    alert("✅ Password changed successfully!");
                    setShowChangePasswordModal(false);
                    setPinPassword("");
                    setNewPassword("");
                    setConfirmPassword("");
                    setPasswordError("");
                  } catch (err) {
                    setPasswordError(`❌ ${err}`);
                  }
                }}
              >
                Change Password
              </button>
              <button onClick={() => {
                setShowChangePasswordModal(false);
                setPinPassword("");
                setNewPassword("");
                setConfirmPassword("");
                setPasswordError("");
              }}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Change PIN Modal */}
      {showChangePinModal && (
        <div className="modal">
          <div className="modal-content">
            <h2>Change Confirmation PIN</h2>
            <input
              type="password"
              value={pinPassword}
              onChange={(e) => setPinPassword(e.target.value)}
              placeholder="Enter current password"
            />
            {passwordError && <p className="error">{passwordError}</p>}
            <div className="modal-actions">
              <button
                onClick={async () => {
                  if (!pinPassword) {
                    setPasswordError("Password is required");
                    return;
                  }
                  try {
                    const newPin = await invoke<string>("change_user_pin", {
                      userId: currentUserId,
                      password: pinPassword
                    });
                    setUserPin(newPin);
                    alert(`✅ New PIN generated: ${newPin}\nPlease save it securely!`);
                    setShowChangePinModal(false);
                    setPinPassword("");
                    setPasswordError("");
                  } catch (err) {
                    setPasswordError(`❌ ${err}`);
                  }
                }}
              >
                Generate New PIN
              </button>
              <button onClick={() => {
                setShowChangePinModal(false);
                setPinPassword("");
                setPasswordError("");
              }}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* PIN Display Modal */}
      {showPinDisplayModal && (
        <div className="modal">
          <div className="modal-content">
            <h2>🔐 Your Confirmation PIN</h2>
            <div className="pin-display-large">
              <strong>{userPin ?? "PIN not available"}</strong>
            </div>
            <p className="pin-warning">⚠️ Please save this PIN securely. You'll need it for wipe confirmations.</p>
            <div className="modal-actions">
              <button onClick={() => setShowPinDisplayModal(false)}>Close</button>
            </div>
          </div>
        </div>
      )}



      {/* Upload Certificate Modal */}
      {showUploadModal && (
        <div className="modal">
          <div className="modal-content">
            <h2>Upload Certificate</h2>
            <input
              type="file"
              accept=".json,.pdf"
              onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
            />
            <p style={{fontSize: '0.9em', color: '#666', marginTop: '8px'}}>
              📄 For Audit Certificate: Select the <strong>.json</strong> file<br/>
              📄 For PDF Certificate: Select the <strong>.pdf</strong> file
            </p>
            <div className="modal-actions">
              <button
                onClick={async () => {
                  if (!selectedFile) {
                    alert("⚠️ Please select a certificate file!");
                    return;
                  }

                  try {
                    let isValid = false;

                    if (selectedCertType === "audit") {
                      // Handle JSON audit certificate verification
                      const readFileAsText = (file: File): Promise<string> =>
                        new Promise((resolve, reject) => {
                          const reader = new FileReader();
                          reader.onload = () => {
                            const result = reader.result as string;
                            if (!result || result.trim() === '') {
                              reject(new Error('File is empty or could not be read'));
                            } else {
                              resolve(result);
                            }
                          };
                          reader.onerror = () => reject(reader.error || new Error('Failed to read file'));
                          reader.readAsText(file, 'UTF-8');
                        });

                      let content = '';
                      try {
                        content = await readFileAsText(selectedFile);
                        console.log('File content length:', content.length);
                        console.log('First 100 chars:', content.substring(0, 100));
                        
                        // Validate JSON format
                        const parsedCert = JSON.parse(content);
                        
                        // Check if it's an audit certificate structure
                        if (!parsedCert.certificate_id || !parsedCert.issuer || !parsedCert.subject) {
                          throw new Error('Invalid audit certificate structure. Missing required fields.');
                        }
                        
                        isValid = await invoke<boolean>("verify_audit_certificate", {
                          certJson: content,
                        });
                      } catch (parseError) {
                        if (content && content.includes('Secure Wipe Certificate')) {
                          throw new Error('You selected a text certificate. Please select the JSON audit certificate file instead.');
                        }
                        throw new Error(`Invalid JSON format: ${parseError}`);
                      }
                    } else if (selectedCertType === "pdf") {
                      // Handle PDF verification
                      const fileBuffer = await selectedFile.arrayBuffer();
                      const uint8Array = new Uint8Array(fileBuffer);
                      
                      isValid = await invoke<boolean>("verify_certificate_pdf", {
                        pdfData: Array.from(uint8Array),
                      });
                    } else {
                      alert("⚠️ Please select certificate type first!");
                      return;
                    }

                    if (isValid) {
                      setErrorMessage("✅ Certificate is valid and untampered!");
                    } else {
                      setErrorMessage("❌ Certificate verification failed.");
                    }
                  } catch (err) {
                    console.error('Certificate verification error:', err);
                    const sanitizedError = String(err).replace(/<[^>]*>/g, '');
                    setErrorMessage(`⚠️ Error verifying certificate: ${sanitizedError}`);
                  }

                  setShowUploadModal(false);
                  setSelectedFile(null);
                  setSelectedCertType(null);
                }}
              >
                Verify
              </button>
              <button onClick={() => {
                setShowUploadModal(false);
                setSelectedFile(null);
                setSelectedCertType(null);
              }}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Certificate Type Selection Modal */}
      {showCertTypeModal && (
        <div className="modal">
          <div className="modal-content">
            <h2>Select Certificate Type</h2>
            <div className="wipe-modes">
              <div
                className="wipe-option"
                onClick={() => handleCertTypeSelection("audit")}
              >
                <strong>Audit Certificate (JSON)</strong>
                <br />
                <span>Cryptographically signed, legally admissible</span>
              </div>
              <div
                className="wipe-option"
                onClick={() => handleCertTypeSelection("pdf")}
              >
                <strong>PDF Certificate</strong>
                <br />
                <span>Human readable format</span>
              </div>
            </div>
            <div className="modal-actions">
              <button onClick={() => setShowCertTypeModal(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Bootable USB Modal */}
      <BootableModal 
        show={showBootableModal} 
        onClose={() => setShowBootableModal(false)} 
      />
      
      {/* PXE Boot Modal */}
      <PxeBootModal 
        isOpen={showPxeBootModal} 
        onClose={() => setShowPxeBootModal(false)}
        theme={theme}
      />
      
      {/* Geofence Modal */}
      <GeofenceModal 
        isOpen={showGeofenceModal} 
        onClose={() => setShowGeofenceModal(false)}
        sensitiveFiles={sensitiveFiles}
        userId={currentUserId || 0}
      />
      


      {/* Unlock Modal */}
      {showUnlockModal && (
        <div className="modal">
          <div className="modal-content">
            <h2>🔓 Unlock Sensitive Files</h2>
            <input
              type="password"
              value={unlockPin}
              onChange={(e) => setUnlockPin(e.target.value)}
              placeholder="Enter PIN to unlock files"
            />
            {unlockError && <p className="error">{unlockError}</p>}
            <div className="modal-actions">
              <button
                onClick={async () => {
                  if (!unlockPin) {
                    setUnlockError("PIN is required");
                    return;
                  }
                  try {
                    const isValid = await invoke<boolean>("verify_user_pin", {
                      userId: currentUserId,
                      pin: unlockPin,
                    });
                    if (isValid) {
                      await invoke("unlock_sensitive_files", {
                        filePaths: sensitiveFiles,
                        userId: currentUserId
                      });
                      setFilesLocked(false);
                      setShowUnlockModal(false);
                      setUnlockPin("");
                      setUnlockError("");
                      alert("🔓 Files unlocked successfully!");
                    } else {
                      setUnlockError("❌ Incorrect PIN");
                    }
                  } catch (err) {
                    setUnlockError(`❌ Error: ${err}`);
                  }
                }}
              >
                Unlock
              </button>
              <button
                onClick={() => {
                  setShowUnlockModal(false);
                  setUnlockPin("");
                  setUnlockError("");
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Progress Modal */}
      {showProgressModal && (
        <div className={`${progressMinimized ? 'progress-minimized' : 'modal'}`}>
          <div className={`modal-content ${progressMinimized ? 'minimized-content' : ''}`}>
            <div className="modal-header">
              <h2>🔄 Secure Wipe in Progress</h2>
              <div className="modal-header-buttons">
                <button 
                  className="cancel-btn"
                  onClick={() => setShowCancelConfirm(true)}
                >
                  ❌ Cancel
                </button>
                <button 
                  className="minimize-btn"
                  onClick={() => setProgressMinimized(!progressMinimized)}
                >
                  {progressMinimized ? '🔼' : '🔽'}
                </button>
              </div>
            </div>
            {!progressMinimized && (
              <>
                <div className="progress-container">
                  <div className="progress-info">
                    <p>Pass {wipeProgress.pass || 1} of {wipeProgress.totalPasses || 7}</p>
                    <p>{wipeProgress.progress || 0}% Complete</p>
                    <p>{Math.round((wipeProgress.bytesWritten || 0) / (1024 * 1024))} MB / {Math.round((wipeProgress.totalBytes || 1) / (1024 * 1024))} MB</p>
                  </div>
                  <div className="progress-bar">
                    <div 
                      className="progress-fill" 
                      style={{ width: `${wipeProgress.progress}%` }}
                    ></div>
                  </div>
                </div>
                <p className="progress-warning">⚠️ Do not disconnect the drive or close the application</p>
              </>
            )}
          </div>
        </div>
      )}

      {/* Cancel Confirmation Modal */}
      {showCancelConfirm && (
        <div className="modal">
          <div className="modal-content">
            <h2>⚠️ Cancel Wipe Operation</h2>
            <p>Are you sure you want to cancel the wipe operation? This may leave data in an inconsistent state.</p>
            <input
              type="password"
              value={cancelPin}
              onChange={(e) => setCancelPin(e.target.value)}
              placeholder="Enter PIN to confirm cancellation"
            />
            {cancelError && <p className="error">{cancelError}</p>}
            <div className="modal-actions">
              <button
                onClick={async () => {
                  if (!cancelPin) {
                    setCancelError("PIN is required to cancel");
                    return;
                  }
                  try {
                    const isValid = await invoke<boolean>("verify_user_pin", {
                      userId: currentUserId,
                      pin: cancelPin,
                    });
                    if (!isValid) {
                      setCancelError("❌ Incorrect PIN");
                      return;
                    }
                    
                    // Cancel the wipe operation
                    try {
                      const selected = drives.filter((d) => d.selected).map((d) => d.name);
                      await invoke("cancel_wipe_operation", {
                        userId: currentUserId,
                        drive: selected.join(", "),
                        wipeMode: selectedWipe === "Purge" ? selectedRandomMethod : selectedWipe,
                        username: username,
                      });
                      setShowProgressModal(false);
                      setShowCancelConfirm(false);
                      setCancelPin("");
                      setCancelError("");
                      setErrorMessage("⚠️ Wipe operation cancelled - Certificate generated");
                    } catch (err) {
                      setCancelError(`Failed to cancel operation: ${err}`);
                    }
                  } catch (err) {
                    setCancelError(`Error verifying PIN: ${err}`);
                  }
                }}
              >
                Confirm Cancel
              </button>
              <button
                onClick={() => {
                  setShowCancelConfirm(false);
                  setCancelPin("");
                  setCancelError("");
                }}
              >
                Continue Wipe
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Help Modal */}
      {showHelpModal && (
        <div className="modal">
          <div className="modal-content" style={{maxWidth: '800px', width: '90vw', maxHeight: '80vh', overflowY: 'auto'}}>
            <h2>🛡️ Secure Wipe Features</h2>
            
            <div className="wipe-modes">
              <div className="wipe-option">
                <strong>🏠 Wipe Methods</strong>
                <br />
                <span><strong>Clear:</strong> Quick removal (recoverable) - Fast deletion for non-sensitive data</span>
                <br />
                <span><strong>Random Byte:</strong> Secure wipe (hard to recover) - Multiple pass overwriting with random data</span>
                <br />
                <span><strong>Destroy:</strong> Cryptographic erase (irrecoverable) - Military-grade secure deletion</span>
              </div>

              <div className="wipe-option">
                <strong>📊 Dashboard</strong>
                <br />
                <span>View drive information, browse files, and monitor storage usage across all connected drives</span>
              </div>

              <div className="wipe-option">
                <strong>📜 Certificates</strong>
                <br />
                <span>Generate and download tamper-proof certificates as evidence of secure wipe operations</span>
              </div>

              <div className="wipe-option">
                <strong>🔒 Sensitive Files</strong>
                <br />
                <span>Protect important files by automatically locking them after failed PIN attempts during wipe operations</span>
              </div>

              <div className="wipe-option">
                <strong>💿 Bootable USB/ISO</strong>
                <br />
                <span>Create bootable media for OS-independent secure wiping with complete hardware access</span>
              </div>
              
              <div className="wipe-option">
                <strong>🌐 PXE Network Boot</strong>
                <br />
                <span>Deploy network-based wiping for 1000+ devices simultaneously. Automated PXE server with client monitoring and certificate collection</span>
              </div>

              <div className="wipe-option">
                <strong>🔐 Security Features</strong>
                <br />
                <span>PIN protection, password management, certificate verification, and file locking for maximum security</span>
              </div>
            </div>

            <div className="modal-actions">
              <button className={`modal-close-btn theme-${theme}`} onClick={() => setShowHelpModal(false)}>Close</button>
            </div>
          </div>
        </div>
      )}

    </main>
  );
}

// Dashboard Component
import BootablePage from "./BootablePage";
import LandingPage from "./LandingPage";

function Dashboard({
  setCurrentPage,
  theme,
}: {
  setCurrentPage: (page: "home" | "dashboard" | "certificates" | "sensitive-files" | "bootable") => void;
  theme: string;
}) {
  const [driveInfo, setDriveInfo] = useState<
    { name: string; total: number; free: number }[]
  >([]);
  const [selectedDrive, setSelectedDrive] = useState<string | null>(null);
  const [currentPath, setCurrentPath] = useState<string>("");
  const [files, setFiles] = useState<{ name: string; size: number; isDirectory: boolean; fullPath: string }[]>([]);
  const [search, setSearch] = useState("");
  const [pathHistory, setPathHistory] = useState<string[]>([]);

  useEffect(() => {
    const fetchDriveInfo = async () => {
      try {
        const info = await invoke<[string, number, number][]>("drive_info");
        setDriveInfo(
          info.map(([name, total, free]) => ({ name, total, free }))
        );
      } catch (err) {
        console.error("Failed to fetch drive info:", err);
      }
    };
    fetchDriveInfo();
  }, []);

  const handleDriveClick = async (drive: string) => {
    setSelectedDrive(drive);
    setCurrentPath(drive);
    setPathHistory([]);
    await loadFiles(drive);
  };

  const loadFiles = async (path: string) => {
    try {
      const filesList = await invoke<Array<[string, number, boolean, string]>>("list_all_files", { path });
      setFiles(filesList.map(([name, size, isDirectory, fullPath]) => ({ name, size, isDirectory, fullPath })));
    } catch (err) {
      console.error("Error listing files:", err);
    }
  };

  const handleFileClick = async (file: { name: string; size: number; isDirectory: boolean; fullPath: string }) => {
    if (file.isDirectory) {
      setPathHistory(prev => [...prev, currentPath]);
      setCurrentPath(file.fullPath);
      await loadFiles(file.fullPath);
    }
  };

  const handleBackClick = async () => {
    if (pathHistory.length > 0) {
      const previousPath = pathHistory[pathHistory.length - 1];
      setPathHistory(prev => prev.slice(0, -1));
      setCurrentPath(previousPath);
      await loadFiles(previousPath);
    } else {
      setSelectedDrive(null);
      setCurrentPath("");
    }
  };

  const formatSize = (bytes: number) => {
    if (bytes === 0) return "—";
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
  };

  const filteredFiles = files.filter((f) =>
    f.name.toLowerCase().includes(search.toLowerCase())
  );
  const totalFilteredSize = filteredFiles.reduce((acc, f) => acc + f.size, 0);

  return (
    <div className={`dashboard-full theme-${theme}`}>
      <div className="dashboard-scrollable">
        {selectedDrive ? (
          <>
            <div className="breadcrumb">
              <h2>📁 {currentPath}</h2>
            </div>
            <input
              type="text"
              placeholder="🔍 Search files..."
              className="search-bar"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <div className="file-grid-container">
              <ul className="file-grid">
                {filteredFiles.map((f) => (
                  <li 
                    key={f.fullPath} 
                    className={`file-card ${f.isDirectory ? 'directory' : 'file'}`}
                    onClick={() => handleFileClick(f)}
                  >
                    <div className="file-info">
                      <span className="file-icon">
                        {f.isDirectory ? '📁' : '📄'}
                      </span>
                      <div className="file-details">
                        <span className="file-name">{f.name}</span>
                        <span className="file-size">{f.isDirectory ? 'Directory' : formatSize(f.size)}</span>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
            <p className="file-summary">
              Showing {filteredFiles.length} items — Total size:{" "}
              {formatSize(totalFilteredSize)}
            </p>
            <button onClick={handleBackClick} className="back-btn">
              ⬅ {pathHistory.length > 0 ? 'Back' : 'Back to Drive Dashboard'}
            </button>
          </>
        ) : (
          <>
            <h2>Drive Dashboard</h2>
            <div className="drive-dashboard">
              {driveInfo.map((d) => {
                const used = d.total - d.free;
                const percent = d.total ? Math.round((used / d.total) * 100) : 0;
                return (
                  <div
                    key={d.name}
                    className="drive-dashboard-item"
                    onClick={() => handleDriveClick(d.name)}
                  >
                    <h3>{d.name}</h3>
                    <div className="storage-bar">
                      <div
                        className="storage-used"
                        style={{ width: `${percent}%` }}
                      ></div>
                    </div>
                    <small>
                      {Math.round(used / 1e9)} GB used /{" "}
                      {Math.round(d.total / 1e9)} GB total
                    </small>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// Certificates Component (full center width)
function Certificates({ userId }: { userId: number }) {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [expandedCert, setExpandedCert] = useState<number | null>(null);
  const [username, setUsername] = useState("");
  const [currentUserId, setCurrentUserId] = useState<number | null>(null);
  
  useEffect(() => {
    // Get current user info for audit certificate generation
    const token = sessionStorage.getItem("authToken");
    if (token) {
      invoke<any>("verify_token", { token }).then(user => {
        setUsername(user.username);
        setCurrentUserId(user.id);
      }).catch(() => {});
    }
  }, []);

  useEffect(() => {
    const fetchCertificates = async () => {
      try {
        const result = await invoke<Certificate[]>("list_certificates", {
          userId,
        });
        setCerts(result);
      } catch (err) {
        console.error("Error fetching certificates:", err);
      }
    };
    fetchCertificates();
  }, [userId]);

  const toggleCert = (id: number) => {
    setExpandedCert(expandedCert === id ? null : id);
  };

  return (
    <div className="certificates-container">
      <h2>My Certificates</h2>
      <ul className="cert-list">
        {certs.map((cert) => (
          <li key={cert.id} className="cert-item">
            <div className="cert-summary" onClick={() => toggleCert(cert.id)}>
              <strong>{cert.drive}</strong> — {cert.wipe_mode}
              <span className={`status-badge ${cert.status === 'completed' ? 'completed' : 'incomplete'}`}>
                {cert.status === 'completed' ? '✅' : '❌'} {cert.status}
              </span>
              <span className="expand-icon">
                {expandedCert === cert.id ? "▲" : "▼"}
              </span>
            </div>
            {expandedCert === cert.id && (
              <div className="cert-details">
                <p>
                  <strong>Timestamp:</strong> {cert.timestamp}
                </p>
                <p>
                  <strong>Device:</strong> {cert.device_id}
                </p>
                <p>
                  <strong>Status:</strong> 
                  <span className={`status-badge ${cert.status === 'completed' ? 'completed' : 'incomplete'}`}>
                    {cert.status === 'completed' ? '✅' : '❌'} {cert.status}
                  </span>
                </p>
                <p>
                  <strong>Content:</strong>
                  <br />
                  <pre>{cert.content}</pre>
                </p>

                <div style={{display: 'flex', gap: '10px'}}>
                  <button 
                    className="back-btn"
                    onClick={async () => {
                      try {
                        const auditCert = await invoke("generate_audit_certificate", {
                          drive: cert.drive,
                          wipeMode: cert.wipe_mode,
                          user: username,
                          complianceStandard: "NIST 800-88, DoD 5220.22-M",
                          userId: currentUserId,
                          status: cert.status,
                        });
                        
                        const filename = `audit_certificate_${cert.drive.replace(/[:\\\s]/g, '_')}_${Date.now()}.json`;
                        await invoke("download_certificate", {
                          content: auditCert,
                          filename
                        });
                        
                        // Make the downloaded file read-only
                        setTimeout(async () => {
                          try {
                            const downloadsPath = await invoke<string>("select_folder");
                            const filePath = `${downloadsPath}\\${filename}`;
                            await invoke("make_audit_certificate_readonly", { filePath });
                          } catch (err) {
                            console.log("Could not make file read-only:", err);
                          }
                        }, 2000);
                      } catch (err) {
                        alert(`Error: ${err}`);
                      }
                    }}
                  >
                    Download Audit JSON
                  </button>
                  <button 
                    className="back-btn"
                    onClick={async () => {
                      try {
                        await invoke("download_certificate_pdf", {
                          drive: cert.drive,
                          wipeMode: cert.wipe_mode,
                          deviceId: cert.device_id,
                          timestamp: cert.timestamp,
                          status: cert.status,
                          filename: `certificate_${cert.drive.replace(/[:\\\s]/g, '_')}_${cert.timestamp.replace(/[:\s]/g, '_')}.pdf`
                        });
                      } catch (err) {
                        alert(`Error downloading certificate: ${err}`);
                      }
                    }}
                  >
                    Download PDF
                  </button>
                </div>
              </div>
              
            )}
          </li>
          
        ))}
      </ul>
    </div>
  );
}



export default App;
