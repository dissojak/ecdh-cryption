import { useState } from 'react';
import { api } from '../lib/api';

export default function Signup() {
  const [form, setForm] = useState({ username: '', email: '', password: '', pin: '' });
  const [loading, setLoading] = useState(false);
  async function submit() {
    try {
      setLoading(true);
      await api('/auth/signup', { method: 'POST', body: JSON.stringify(form) });
      alert('Signup successful. Please login.');
      window.location.href = '/login';
    } catch (e) {
      alert(e.message);
    } finally {
      setLoading(false);
    }
  }
  return (
    <div className="max-w-md mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">Sign Up</h1>
      {['username','email','password','pin'].map((k) => (
        <input key={k} type={k==='password' || k==='pin' ? 'password':'text'} placeholder={k}
          className="w-full border p-2 mb-2" value={form[k]}
          onChange={(e)=>setForm({...form,[k]:e.target.value})} />
      ))}
      <button className="bg-blue-600 text-white px-4 py-2" onClick={submit} disabled={loading}>Sign Up</button>
    </div>
  );
}
