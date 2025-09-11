import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { User, MoreVertical, Sun, Moon, Shield, Lock } from "lucide-react";
import "./App.css";
import Register from "./Register";
import Login from "./Login";

interface Drive {
  name: string;
  selected: boolean;
}

function App() {
  const [authState, setAuthState] = useState<'register' | 'login' | 'authenticated'>('register');
  const [drives, setDrives] = useState<Drive[]>([]);
  const [showConfirm, setShowConfirm] = useState(false);
  const [pin, setPin] = useState("");
  const [error, setError] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [theme, setTheme] = useState("dark-professional");
  const [showProfile, setShowProfile] = useState(false);
  const [username, setUsername] = useState("John Doe");
  const [email, setEmail] = useState("john.doe@email.com");

  const [selectedWipe, setSelectedWipe] = useState<string | null>(null);
  const [privacyMode, setPrivacyMode] = useState(false);
  const [enableEncryption, setEnableEncryption] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  // page navigation
  const [currentPage, setCurrentPage] = useState<"home" | "dashboard">("home");

  const CORRECT_PIN = "1234";

  const toggleProfile = () => setShowProfile(!showProfile);
  const closeProfile = () => setShowProfile(false);

  useEffect(() => {
    if (authState === 'authenticated') {
      const fetchDrives = async () => {
        try {
          const driveList = await invoke<string[]>("list_drives");
          setDrives(driveList.map((d: string) => ({ name: d, selected: false })));
        } catch (err) {
          console.error("Error fetching drives:", err);
        }
      };
      fetchDrives();
    }
  }, [authState]);

  const handleRegisterSuccess = async (token: string, user: any) => {
    // Store token and switch to login
    localStorage.setItem('authToken', token);
    setAuthState('login');
  };

  const handleLoginSuccess = async (token: string, user: any) => {
    // Store token and set authenticated
    localStorage.setItem('authToken', token);
    setAuthState('authenticated');
  };

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    setAuthState('login');
    setShowProfile(false);
  };

  const toggleDrive = (index: number) => {
    const newDrives = [...drives];
    newDrives[index].selected = !newDrives[index].selected;
    setDrives(newDrives);
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
    setShowConfirm(true);
  };

  const confirmDelete = async () => {
    if (pin === CORRECT_PIN) {
      const selected = drives.filter((d) => d.selected).map((d) => d.name);

      try {
        const filePath = await invoke<string>("generate_certificate", {
          drive: selected.join(", "),
          wipeMode: selectedWipe,
          user: username,
        });

        alert(`✅ Wiping completed!\nCertificate saved at: ${filePath}`);
      } catch (err) {
        alert(`❌ Failed to generate certificate: ${err}`);
      }

      setShowConfirm(false);
      setPin("");
      setError("");
    } else {
      setError("❌ Incorrect PIN. Try again.");
    }
  };

  // Show authentication pages if not authenticated
  if (authState === 'register') {
    return <Register onSuccess={handleRegisterSuccess} onSwitch={() => setAuthState('login')} />;
  }

  if (authState === 'login') {
    return <Login onSuccess={handleLoginSuccess} onSwitch={() => setAuthState('register')} />;
  }

  const handleVerifyCertificate = () => {
    setShowUploadModal(true);
  };
  return (
    <main className={`app-layout theme-${theme}`}>
      {/* Top Bar */}
      <header className="topbar">
        <h1>Secure Wipe</h1>
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
              </div>
              <button className="logout-btn">Change email</button>
              <br />
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
            className={`sidebar-item ${currentPage === "dashboard" ? "active" : ""}`}
            onClick={() => setCurrentPage("dashboard")}
          >
            <span className="sidebar-icon">📊</span>
            <span>Dashboard</span>
          </div>

          <div
            className="sidebar-item sidebar-important"
            onClick={handleVerifyCertificate}
          >
            <span className="sidebar-icon">✅</span>
            <span>Verify Certificate</span>
          </div>

          <div className="sidebar-item" onClick={() => setShowSettings(true)}>
            <MoreVertical className="sidebar-icon" />
            <span>Settings</span>
          </div>


        </div>
      </aside>

      {/* Main Content */}
      <section className="content">
        {currentPage === "home" && (
          <div className="card">
            <h2>Select a Disk</h2>
            <div className="drive-list">
              {drives.map((drive, index) => (
                <div
                  key={drive.name}
                  className={`drive-option ${drive.selected ? "selected" : ""}`}
                  onClick={() => toggleDrive(index)}
                >
                  {drive.name}
                </div>
              ))}
            </div>

            <h3>Wipe Mode</h3>
            <div className="wipe-modes">
              <div
                className={`wipe-option ${selectedWipe === "Clear" ? "selected" : ""}`}
                onClick={() => setSelectedWipe("Clear")}
              >
                <strong>Clear</strong>
                <br />
                <span>Quick removal (Recoverable)</span>
              </div>
              <div
                className={`wipe-option ${selectedWipe === "Purge" ? "selected" : ""}`}
                onClick={() => setSelectedWipe("Purge")}
              >
                <strong>Random Byte</strong>
                <br />
                <span>Secure Wipe (hard to recover)</span>
              </div>
              <div
                className={`wipe-option ${selectedWipe === "Destroy" ? "selected" : ""}`}
                onClick={() => setSelectedWipe("Destroy")}
              >
                <strong>Destroy</strong>
                <br />
                <span>Cryptographic erase (irrecoverable)</span>
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
      </section>

      {/* Footer */}
      <footer className="footer">
        <nav className="footer-links">
          <a href="#">About</a>
          <a href="#">Contact</a>
          <a href="#">Help</a>
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

      {/* Settings Modal */}
      {showSettings && (
        <div className="modal">
          <div className="modal-content">
            <h2>Settings</h2>
            <div className="settings-section">
              <label>Theme</label>
              <div className="theme-toggle">
                <Sun
                  size={28}
                  className={`theme-icon ${theme === "green-soft" ? "selected" : ""}`}
                  onClick={() => setTheme("green-soft")}
                />
                <Moon
                  size={28}
                  className={`theme-icon ${theme === "dark-professional" ? "selected" : ""}`}
                  onClick={() => setTheme("dark-professional")}
                />
              </div>
            </div>
            <div className="settings-section">
              <label>Privacy & Security</label>
              <div className="privacy-security-options">
                <div
                  className="privacy-option"
                  onClick={() => setPrivacyMode(!privacyMode)}
                >
                  <Shield className="option-icon" />
                  <span>Privacy Mode</span>
                  <input type="checkbox" checked={privacyMode} readOnly />
                </div>
                <div
                  className="privacy-option"
                  onClick={() => setEnableEncryption(!enableEncryption)}
                >
                  <Lock className="option-icon" />
                  <span>Security and password</span>
                </div>
              </div>
            </div>
            <div className="modal-actions">
              <button onClick={() => setShowSettings(false)}>Close</button>
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
              accept=".txt"
              onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
            />
            <div className="modal-actions">
              <button
                onClick={async () => {
                  if (!selectedFile) {
                    alert("⚠️ Please select a certificate file!");
                    return;
                  }
                  try {
                    const readFileAsText = (file: File): Promise<string> => {
                      return new Promise((resolve, reject) => {
                        const reader = new FileReader();

                        reader.onload = () => {
                          resolve(reader.result as string);
                        };

                        reader.onerror = () => {
                          reject(reader.error);
                        };

                        reader.readAsText(file);
                      });
                    };

                    const content = await readFileAsText(selectedFile);
                    const isValid = await invoke<boolean>("verify_certificate", {
                      content,
                    });
                    if (isValid) {
                      alert("✅ Certificate is valid and untampered!");
                    } else {
                      alert("❌ Certificate verification failed (hash mismatch).");
                    }
                  } catch (err) {
                    alert(`⚠️ Error verifying certificate: ${err}`);
                  }
                  setShowUploadModal(false);
                  setSelectedFile(null);
                }}
              >
                Verify
              </button>
              <button onClick={() => setShowUploadModal(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

// Dashboard Page Component
function Dashboard({
  setCurrentPage,
  theme,
}: {
  setCurrentPage: (page: "home" | "dashboard") => void;
  theme: string;
}) {
  const [driveInfo, setDriveInfo] = useState<
    { name: string; total: number; free: number }[]
  >([]);
  const [selectedDrive, setSelectedDrive] = useState<string | null>(null);
  const [files, setFiles] = useState<{ name: string; size: number }[]>([]);
  const [search, setSearch] = useState("");

  useEffect(() => {
    const fetchDriveInfo = async () => {
      try {
        const info = await invoke<[string, number, number][]>("drive_info");
        setDriveInfo(info.map(([name, total, free]) => ({ name, total, free })));
      } catch (err) {
        console.error("Failed to fetch drive info:", err);
      }
    };
    fetchDriveInfo();
  }, []);

  const handleDriveClick = async (drive: string) => {
    setSelectedDrive(drive);
    try {
      const filesList = await invoke<[string, number][]>("list_files", { drive });
      setFiles(filesList.map(([name, size]) => ({ name, size })));
    } catch (err) {
      console.error("Error listing files:", err);
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
            <h2>Files in {selectedDrive}</h2>
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
                  <li key={f.name} className="file-card">
                    <div className="file-info">
                      <span className="file-name">{f.name}</span>
                      <span className="file-size">{formatSize(f.size)}</span>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
            <p className="file-summary">
              Showing {filteredFiles.length} files — Total size: {formatSize(totalFilteredSize)}
            </p>
            <button onClick={() => setSelectedDrive(null)} className="back-btn">
              ⬅ Back to Drive Dashboard
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
                      <div className="storage-used" style={{ width: `${percent}%` }}></div>
                    </div>
                    <small>
                      {Math.round(used / 1e9)} GB used / {Math.round(d.total / 1e9)} GB total
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


export default App;
