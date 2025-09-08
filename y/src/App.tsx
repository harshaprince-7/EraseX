import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

interface Drive {
  name: string;
  selected: boolean;
}

function App() {
  const [drives, setDrives] = useState<Drive[]>([]);

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
    alert(`Wiping drives: ${selected.join(", ")}`);
  };

  return (
    <main className="container">
      <h1 className="title">Select a disk:</h1>

      <div className="drive-list">
        {drives.map((drive, index) => (
          <div key={drive.name} className="drive-item">
            <label>
              <input
                type="checkbox"
                checked={drive.selected}
                onChange={() => toggleDrive(index)}
              />
              <span className="drive-name">{drive.name}</span>
            </label>
          </div>
        ))}
      </div>

      <button className="delete-btn" onClick={handleDelete}>
        Delete Selected
      </button>
    </main>
  );
}

export default App;
