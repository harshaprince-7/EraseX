// components/Register.tsx
import { useState } from 'react';
import { invoke } from "@tauri-apps/api/core";

interface RegisterProps {
  onSuccess: (token: string, user: any, confirmationPin: string) => void;
  onSwitch: () => void;
  onBack: ()=> void;
}

const Register = ({ onSuccess, onSwitch, onBack}: RegisterProps) => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: ''
  });
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    
    try {
     const response = await invoke<{ 
  token: string, 
  user_id: number, 
  username: string, 
  email: string,
  confirmation_pin: string // <- add this
}>('register_user', {
  email: formData.email,
  password: formData.password,
  username: formData.name
});

onSuccess(response.token, {
  id: response.user_id,
  username: response.username,
  email: response.email
}, response.confirmation_pin); // <- pass PIN

    } catch (err) {
      setError(String(err));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-panel reversed">
        <div className="welcome-panel">
          <button className="back-button" onClick={onBack}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M15 18L9 12L15 6" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </button>
          <h1>Hello, User!</h1>
          <p>Enter your personal details and start your journey with us</p>
          <button className="outline-btn" onClick={onSwitch}>
            SIGN IN
          </button>
        </div>
        
        <div className="form-panel">
          <h2>CREATE ACCOUNT</h2>
                    
          <form onSubmit={handleSubmit}>
            <div className="input-group">
              <input
                type="text"
                name="name"
                placeholder="User Name"
                value={formData.name}
                onChange={handleChange}
                required
                disabled={isLoading}
              />
            </div>
            <div className="input-group">
              <input
                type="email"
                name="email"
                placeholder="Email"
                value={formData.email}
                onChange={handleChange}
                required
                disabled={isLoading}
              />
            </div>
            <div className="input-group">
              <input
                type="password"
                name="password"
                placeholder="Password"
                value={formData.password}
                onChange={handleChange}
                required
                disabled={isLoading}
              />
            </div>
            {error && <div className="error-message">{error}</div>}
            <button 
              type="submit" 
              className="submit-btn"
              disabled={isLoading}
            >
              {isLoading ? 'Creating Account...' : 'SIGN UP'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Register;