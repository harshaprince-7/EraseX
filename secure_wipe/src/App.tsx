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
  const [userData, setUserData] = useState({
    id: 0,
    username: "",
    email: ""
  });

  const [selectedWipe, setSelectedWipe] = useState<string | null>(null);

  const [privacyMode, setPrivacyMode] = useState(false);
  const [enableEncryption, setEnableEncryption] = useState(false);

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
    setUserData(user);
    setAuthState('login');
  };

  const handleLoginSuccess = async (token: string, user: any) => {
    // Store token and set authenticated
    localStorage.setItem('authToken', token);
    setUserData(user);
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
          user: userData.username,
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
            <span className="sidebar-username">{userData.username}</span>
          </div>

          {showProfile && (
            <div className="profile-dropdown">
              {/* <img
                src="https://via.placeholder.com/60"
                alt="Profile"
                className="profile-avatar"
              /> */}
              <div className="profile-info">
                <label>Username</label>
                <input
                  type="text"
                  value={userData.username}
                  onChange={(e) => setUserData({...userData, username: e.target.value})}
                /><br/>
                <label>Email</label><br/>
                <input
                  type="email"
                  value={userData.email}
                  onChange={(e) => setUserData({...userData, email: e.target.value})}
                />
              </div>
              <button className="logout-btn">Change email</button><br/><br/>
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

          <div className="sidebar-item" onClick={() => setShowSettings(true)}>
            <MoreVertical className="sidebar-icon" />
            <span>Settings</span>
          </div>

          <div
            className="sidebar-item sidebar-important"
            onClick={() => alert("🔒 Verifying your certificate...")}
          >
            <span className="sidebar-icon">✅</span>
            <span>Verify Certificate</span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <section className="content">
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
              className={`wipe-option ${selectedWipe === "Clear" ? "selected" : ""
                }`}
              onClick={() => setSelectedWipe("Clear")}
            >
              <strong>Clear</strong>
              <br />
              <span>Quick removal (Recoverable)</span>
            </div>
            <div
              className={`wipe-option ${selectedWipe === "Purge" ? "selected" : ""
                }`}
              onClick={() => setSelectedWipe("Purge")}
            >
              <strong>Purge</strong>
              <br />
              <span>Secure Wipe (harder to recover)</span>
            </div>
            <div
              className={`wipe-option ${selectedWipe === "Destroy" ? "selected" : ""
                }`}
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

            {/* Theme Toggle */}
            <div className="settings-section">
              <label>Theme</label>
              <div className="theme-toggle">
                <Sun
                  size={28}
                  className={`theme-icon ${theme === "green-soft" ? "selected" : ""
                    }`}
                  onClick={() => setTheme("green-soft")}
                />
                <Moon
                  size={28}
                  className={`theme-icon ${theme === "dark-professional" ? "selected" : ""}`}
                  onClick={() => setTheme("dark-professional")}
                  />
              </div>
            </div>

            {/* Privacy & Security */}
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
                  onClick={() =>
                    setEnableEncryption(!enableEncryption)
                  }
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
    </main>
  );
}

export default App;
