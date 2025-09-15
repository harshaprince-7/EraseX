// components/Login.tsx
import { useState } from 'react';
import { invoke } from "@tauri-apps/api/core";

interface LoginProps {
  onSuccess: (token: string, user: any, pin: string) => void; // updated to include PIN
  onSwitch: () => void;
}

const Login = ({ onSuccess, onSwitch }: LoginProps) => {
  const [formData, setFormData] = useState({
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
      // Include confirmation_pin in the response type
      const response = await invoke<{ 
        token: string, 
        user_id: number, 
        username: string, 
        email: string,
        confirmation_pin: string // ✅ new
      }>('login_user', {
        email: formData.email,
        password: formData.password
      });
      
      // Pass PIN to onSuccess
      onSuccess(
        response.token,
        {
          id: response.user_id,
          username: response.username,
          email: response.email
        },
        response.confirmation_pin // ✅ pass PIN
      );
    } catch (err) {
      setError(String(err));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-panel">
        <div className="welcome-panel">
          <h1>Welcome Back!</h1>
          <p>To keep connected with us please login with your personal info</p>
          <button className="outline-btn" onClick={onSwitch}>
            SIGN UP
          </button>
        </div>
        
        <div className="form-panel">
          <h2>SIGN IN</h2>
          
          <form onSubmit={handleSubmit}>
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
            <div className='input-group'>
               <button 
                type="submit" 
                className="submit-btn"
                disabled={isLoading}
              >
                {isLoading ? 'Signing In...' : 'SIGN IN'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Login;
