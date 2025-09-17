import { useState } from 'react';
import { api } from '../lib/api';
import { useEffect } from 'react';
import { decryptVault, cacheSessionKey, cachePrivateJwk } from '../lib/crypto';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [pin, setPin] = useState('');
  const [needsPin, setNeedsPin] = useState(false);
  const [vault, setVault] = useState(null);
  const [pinRefreshRequired, setPinRefreshRequired] = useState(false);
  useEffect(() => {
    // If token and session key are present, go to chat
    const token = localStorage.getItem('token');
    const expiry = parseInt(localStorage.getItem('sessionKeyExpiry') || '0', 10);
    const key = localStorage.getItem('sessionKey');
    if (token && key && Date.now() < expiry) {
      window.location.href = '/chat';
    }
  }, []);
  async function login() {
    try {
      const { token, user, encryptedVault, pinRefreshRequired } = await api('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
      localStorage.setItem('token', token);
      setVault(encryptedVault);
      setNeedsPin(true);
      setPinRefreshRequired(!!pinRefreshRequired);
      if (pinRefreshRequired) {
        // We'll prompt user to refresh PIN after unlocking
        console.info('PIN refresh required');
      }
    } catch (e) {
      alert(e.message);
    }
  }
  async function enterPin() {
    try {
      const result = await decryptVault(vault, pin);
      if (result && result.ecdhPrivateJwk) {
        cachePrivateJwk(result.ecdhPrivateJwk, 5 * 60 * 1000);
      }
      if (result && result.legacySessionKeyHex) {
        cacheSessionKey(result.legacySessionKeyHex, 3 * 60 * 1000);
        // Migrate account to ECDH now so conversations use shared keys
        try {
          await api('/auth/migrate-ecdh', { method: 'POST', body: JSON.stringify({ pin }) });
          // Refetch vault and store private JWK
          const meRes = await api('/auth/me');
          const migrated = await decryptVault(meRes.encryptedVault, pin);
          if (migrated && migrated.ecdhPrivateJwk) {
            cachePrivateJwk(migrated.ecdhPrivateJwk, 5 * 60 * 1000);
          }
        } catch (_) { /* ignore */ }
      }
      if (pinRefreshRequired) {
        try {
          await api('/auth/refresh-pin', { method: 'POST', body: JSON.stringify({ pin }) });
        } catch (e) {
          console.warn('PIN refresh failed:', e.message);
        }
      }
      window.location.href = '/chat';
    } catch (e) {
      alert('Invalid PIN');
    }
  }
  return (
    <div className="max-w-md mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">Login</h1>
      <input className="w-full border p-2 mb-2" placeholder="email" value={email} onChange={e=>setEmail(e.target.value)} />
      <input className="w-full border p-2 mb-2" placeholder="password" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
      <button className="bg-blue-600 text-white px-4 py-2" onClick={login}>Login</button>
      {needsPin && (
        <div className="mt-4">
          <input className="w-full border p-2 mb-2" placeholder="PIN" type="password" value={pin} onChange={e=>setPin(e.target.value)} />
          <button className="bg-green-600 text-white px-4 py-2" onClick={enterPin}>Enter PIN</button>
          {pinRefreshRequired && <div className="text-xs text-orange-600 mt-2">Security reminder: your PIN backup needs refresh. We'll update it after unlock.</div>}
        </div>
      )}
      <div className="mt-4">
        <a className="text-blue-600 underline" href="/signup">Create an account</a>
      </div>
    </div>
  );
}
