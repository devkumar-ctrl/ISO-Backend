import express from 'express';
import cors from 'cors';
import { config } from './config.js';
import questionnaireRouter from './routes/questionnaire.js';
import authRouter from './routes/auth.js';
import tasksRouter from './routes/tasks.js';

const app = express();

// Raw body parser for JSON
app.use('/api/questionnaire/answer', express.json({ type: 'application/json', limit: '10mb' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({
  origin: config.corsOrigin,
  credentials: true
}));

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'ITC ISMS API',
    version: '1.0.0',
    timestamp: new Date().toISOString() 
  });
});

// Metadata endpoint
app.get('/api/metadata', (req, res) => {
  res.json({ 
    name: 'ISO 27001 Metadata',
    version: '1.0.0',
    clauses: 6,
    questions: 33,
    blocks: 8
  });
});

// Routes
app.use('/api/questionnaire', questionnaireRouter);
app.use('/api/auth', authRouter);
app.use('/api/tasks', tasksRouter);

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(err.status || 500).json({
    error: err.message,
    code: err.code
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Start server
const PORT = config.port;
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════╗
║   ITC ISMS Platform - Backend API             ║
║   Version: 1.0.0                           ║
║   Running on http://localhost:${PORT}                 ║
╚═══════════════════════════════════════════════╝
  `);
});

export default app;