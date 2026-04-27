import { createClient } from '@supabase/supabase-js';
import { config } from './config.js';

// Only initialize Supabase if credentials are provided
let supabase = null;

if (config.supabase.url && config.supabase.anonKey) {
  supabase = createClient(
    config.supabase.url,
    config.supabase.anonKey,
    {
      auth: {
        autoRefreshToken: true,
        persistSession: false
      }
    }
  );
}

export const serviceClient = config.supabase.serviceKey && config.supabase.url
  ? createClient(config.supabase.url, config.supabase.serviceKey)
  : null;

export default supabase;