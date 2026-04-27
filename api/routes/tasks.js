import express from 'express';
import { v4 as uuidv4 } from 'uuid';

const router = express.Router();

const activeTasks = new Map();

// Task statuses
const STATUS = {
  PENDING: 'pending',
  IN_PROGRESS: 'in_progress',
  REVIEW: 'review',
  COMPLETED: 'completed'
};

// ============================================================================
// Task Routes
// ============================================================================

// Create new task/review item
router.post('/tasks', async (req, res) => {
  try {
    const { title, description, type, assessmentId, questionId, priority = 'medium' } = req.body;
    const taskId = uuidv4();

    const task = {
      id: taskId,
      title,
      description,
      type: type || 'review', // review, gap_analysis, risk, soa
      assessmentId,
      questionId,
      priority,
      status: STATUS.PENDING,
      position: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    activeTasks.set(taskId, task);

    res.json({ taskId, task });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all tasks (optionally filtered by assessment)
router.get('/tasks', async (req, res) => {
  try {
    const { assessmentId, status } = req.query;
    let tasks = Array.from(activeTasks.values());

    if (assessmentId) {
      tasks = tasks.filter(t => t.assessmentId === assessmentId);
    }
    if (status) {
      tasks = tasks.filter(t => t.status === status);
    }

    res.json({ tasks });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get kanban view
router.get('/tasks/kanban', async (req, res) => {
  try {
    const { assessmentId } = req.query;
    let tasks = Array.from(activeTasks.values());

    if (assessmentId) {
      tasks = tasks.filter(t => t.assessmentId === assessmentId);
    }

    // Organize by status columns
    const kanban = {
      pending: tasks.filter(t => t.status === STATUS.PENDING),
      in_progress: tasks.filter(t => t.status === STATUS.IN_PROGRESS),
      review: tasks.filter(t => t.status === STATUS.REVIEW),
      completed: tasks.filter(t => t.status === STATUS.COMPLETED)
    };

    res.json({ kanban });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update task status (for drag-drop)
router.patch('/tasks/:taskId', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { status, position } = req.body;

    const task = activeTasks.get(taskId);
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }

    if (status) task.status = status;
    if (position !== undefined) task.position = position;
    task.updatedAt = new Date().toISOString();

    activeTasks.set(taskId, task);

    res.json({ task });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete task
router.delete('/tasks/:taskId', async (req, res) => {
  try {
    const { taskId } = req.params;
    activeTasks.delete(taskId);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Batch create tasks (e.g., from questionnaire completion)
router.post('/tasks/batch', async (req, res) => {
  try {
    const { assessmentId, questions, type = 'review' } = req.body;
    const createdTasks = [];

    for (const q of questions) {
      const taskId = uuidv4();
      const task = {
        id: taskId,
        title: `Review: ${q.question?.substring(0, 50)}...`,
        description: q.question,
        type,
        assessmentId,
        questionId: q.id,
        priority: 'medium',
        status: STATUS.PENDING,
        position: createdTasks.length,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      activeTasks.set(taskId, task);
      createdTasks.push(task);
    }

    res.json({ tasks: createdTasks });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;