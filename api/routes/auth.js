import express from 'express';
import supabase from '../supabase.js';

const router = express.Router();

// ============================================================================
// Auth Routes (Proxy to Supabase Auth)
// ============================================================================

// Register new user
router.post('/signup', async (req, res) => {
  try {
    const { email, password, organization } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          organization: organization || 'ITC India'
        }
      }
    });

    if (error) throw error;

    res.json({
      user: data.user,
      session: data.session
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(400).json({ error: error.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) throw error;

    res.json({
      user: data.user,
      session: data.session
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ error: error.message });
  }
});

// Logout
router.post('/logout', async (req, res) => {
  try {
    const { access_token } = req.body;

    if (access_token) {
      const { error } = await supabase.auth.signOut();
      if (error) throw error;
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get current user
router.get('/user', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ error: 'No authorization header' });
    }

    const token = authHeader.replace('Bearer ', '');
    
    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error) throw error;
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    res.json({ user });
  } catch (error) {
    console.error('User error:', error);
    res.status(401).json({ error: error.message });
  }
});

// Refresh session
router.post('/refresh', async (req, res) => {
  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({ error: 'Refresh token required' });
    }

    const { data, error } = await supabase.auth.refreshSession({ refresh_token });

    if (error) throw error;

    res.json({
      user: data.user,
      session: data.session
    });
  } catch (error) {
    console.error('Refresh error:', error);
    res.status(401).json({ error: error.message });
  }
});

// Reset password
router.post('/reset-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    const { data, error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: process.env.PASSWORD_REDIRECT_URL || 'http://localhost:5173'
    });

    if (error) throw error;

    res.json({ success: true });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(400).json({ error: error.message });
  }
});

// Update password
router.post('/update-password', async (req, res) => {
  try {
    const { access_token, newPassword } = req.body;

    if (!access_token || !newPassword) {
      return res.status(400).json({ error: 'Access token and new password required' });
    }

    const { data, error } = await supabase.auth.updateUser(access_token, {
      password: newPassword
    });

    if (error) throw error;

    res.json({ user: data.user });
  } catch (error) {
    console.error('Update password error:', error);
    res.status(400).json({ error: error.message });
  }
});

export default router;