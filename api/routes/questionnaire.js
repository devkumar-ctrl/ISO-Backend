import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import AdaptiveEngine from '../engine/AdaptiveEngine.js';

const router = express.Router();

const activeAssessments = new Map();
let metadata;

function loadMetadata() {
  if (!metadata) {
    const dataPath = path.join(__dirname, '..', 'data', 'iso27001_metadata.json');
    const data = fs.readFileSync(dataPath, 'utf8');
    metadata = JSON.parse(data);
  }
  return metadata;
}

// Initialize new assessment
router.post('/init', async (req, res) => {
  try {
    const { mode = 'detailed', userId, organizationId } = req.body;
    const assessmentId = uuidv4();

    const engine = new AdaptiveEngine({ mode, debug: true });
    const data = loadMetadata();
    engine.loadMetadata(data);
    engine.initializeFlow(mode);

    const assessment = {
      id: assessmentId,
      engine,
      mode,
      userId,
      organizationId,
      status: 'in_progress',
      createdAt: new Date().toISOString()
    };

    activeAssessments.set(assessmentId, assessment);

    const nextQ = engine.getNextQuestion();

    res.json({
      assessmentId,
      mode,
      questionsPending: engine.queueManager.queue.length,
      currentQuestion: nextQ
    });
  } catch (error) {
    console.error('Init error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get current question
router.get('/current/:assessmentId', async (req, res) => {
  try {
    const { assessmentId } = req.params;
    const assessment = activeAssessments.get(assessmentId);

    if (!assessment) {
      return res.status(404).json({ error: 'Assessment not found' });
    }

    const question = assessment.engine.getNextQuestion();
    res.json({
      assessmentId,
      question,
      progress: assessment.engine.getSummary(),
      isComplete: assessment.engine.isComplete()
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Submit answer via path with query param
router.post('/回答', async (req, res) => {
  try {
    const { assessmentId, questionId } = req.params;
    const answer = req.query.a || '';

    if (!assessmentId || !questionId || !answer) {
      return res.status(400).json({ error: 'Missing required fields', params: req.params, query: req.query });
    }

    const assessment = activeAssessments.get(assessmentId);
    if (!assessment) {
      return res.status(404).json({ error: 'Assessment not found' });
    }

    const result = assessment.engine.processAnswer(questionId, answer);
    res.json({
      assessmentId,
      questionId,
      ...result,
      nextQuestion: assessment.engine.getNextQuestion(),
      isComplete: assessment.engine.isComplete()
    });
  } catch (error) {
    console.error('Answer error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get summary
router.get('/summary/:assessmentId', async (req, res) => {
  try {
    const { assessmentId } = req.params;
    const assessment = activeAssessments.get(assessmentId);

    if (!assessment) {
      return res.status(404).json({ error: 'Assessment not found' });
    }

    const summary = assessment.engine.getSummary();
    const results = assessment.engine.exportResults();

    res.json({ assessmentId, summary, results });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Resume
router.get('/resume/:assessmentId', async (req, res) => {
  try {
    const { assessmentId } = req.params;
    const assessment = activeAssessments.get(assessmentId);

    if (!assessment) {
      return res.status(404).json({ error: 'Assessment not found' });
    }

    res.json({
      assessmentId,
      progress: assessment.engine.getSummary(),
      currentQuestion: assessment.engine.getNextQuestion(),
      answers: assessment.engine.answers,
      isComplete: assessment.engine.isComplete()
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get metadata info
router.get('/metadata', (req, res) => {
  const data = loadMetadata();
  res.json({
    version: data.metadata?.version,
    questions: Object.keys(data.questions).length,
    blocks: Object.keys(data.blocks).length,
    clauses: Object.keys(data.clauses).length
  });
});

// Get blocks and clauses
router.get('/blocks', (req, res) => {
  const data = loadMetadata();
  res.json({ blocks: data.blocks, clauses: data.clauses });
});

export default router;