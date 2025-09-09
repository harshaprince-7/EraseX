import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { User, MoreVertical } from "lucide-react";
import "./App.css";


interface Drive {
  name: string;
  selected: boolean;
}

function App() {
  const [drives, setDrives] = useState<Drive[]>([]);
  const [showConfirm, setShowConfirm] = useState(false);
  const [pin, setPin] = useState("");
  const [error, setError] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [theme, setTheme] = useState("dark-blue");
  const [showProfile, setShowProfile] = useState(false);

  // Profile info
  const [username, setUsername] = useState("John Doe");
  const [email, setEmail] = useState("john.doe@email.com");

  // NEW: Track selected wipe mode
  const [selectedWipe, setSelectedWipe] = useState<string | null>(null);

  const CORRECT_PIN = "1234";

  const toggleProfile = () => setShowProfile(!showProfile);
  const closeProfile = () => setShowProfile(false);

  useEffect(() => {
    const fetchDrives = async () => {
      try {
        const driveList = await invoke<string[]>("list_drives");
        setDrives(driveList.map((d: string) => ({ name: d, selected: false })));
      } catch (err) {
        console.error("Error fetching drives:", err);
      }
    };
    fetchDrives();
  }, []);

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

  const confirmDelete = () => {
    if (pin === CORRECT_PIN) {
      const selected = drives.filter((d) => d.selected).map((d) => d.name);
      alert(`✅ Wiping drives: ${selected.join(", ")} with ${selectedWipe} mode`);
      setShowConfirm(false);
      setPin("");
      setError("");
    } else {
      setError("❌ Incorrect PIN. Try again.");
    }
  };

  const handleLogout = () => {
    alert("You have been logged out!");
    setShowProfile(false);
  };

  return (
    <main className={`container theme-${theme}`}>
      {/* Header */}
      <header className="header">
        <h1>Secure Wipe Utility</h1>
        <div className="header-actions">
          {/* Profile Icon */}
          <div className="profile-wrapper">
            <User className="icon" onClick={toggleProfile} />
            {showProfile && (
              <div className="profile-dropdown">
                <img
                  src="https://via.placeholder.com/60"
                  alt="Profile"
                  className="profile-avatar"
                />
                <div className="profile-info">
                  <label>Username</label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                  <label>Email</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />

                </div>
                <button className="logout-btn">Change email</button><br/>
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

          {/* Settings Icon */}
          <div className="settings-wrapper">
            <MoreVertical className="icon" onClick={() => setShowSettings(true)} />
          </div>
        </div>
      </header>

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
              className={`wipe-option ${selectedWipe === "Clear" ? "selected" : ""}`}
              onClick={() => setSelectedWipe("Clear")}
            >
              <strong>Clear</strong><br/>
              <span>Quick removal(Recoverable)</span>
            </div>
            <div
              className={`wipe-option ${selectedWipe === "Purge" ? "selected" : ""}`}
              onClick={() => setSelectedWipe("Purge")}
            >
              <strong>Purge</strong><br/>
              <span>Secure Wipe(harder to recover)</span>
            </div>
            <div
              className={`wipe-option ${selectedWipe === "Destroy" ? "selected" : ""}`}
              onClick={() => setSelectedWipe("Destroy")}
            >
              <strong>Destroy</strong><br/>
              <span>Cryptogrpahic erase(irrecoverable)</span>
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
            <div className="settings-section">
              <label>Theme</label>
              <select value={theme} onChange={(e) => setTheme(e.target.value)}>
                <option value="dark-blue">Dark Blue</option>
                <option value="green-soft">Green Soft</option>
              </select>
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
