import dotenv from 'dotenv';
dotenv.config();

export const config = {
  supabase: {
    url: process.env.SUPABASE_URL || '',
    anonKey: process.env.SUPABASE_ANON_KEY || '',
    serviceKey: process.env.SUPABASE_SERVICE_KEY || ''
  },
  port: parseInt(process.env.PORT || '3001'),
  corsOrigin: process.env.CORS_ORIGIN || '*',
  enableSupabase: !!(process.env.SUPABASE_URL && process.env.SUPABASE_URL.includes('.supabase.co'))
};