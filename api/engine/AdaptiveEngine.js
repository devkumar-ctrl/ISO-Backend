/**
 * Adaptive Questionnaire Engine
 * 
 * A modular engine that dynamically generates questions based on user responses.
 * Reduces total questions from 80 to ~40-50 using conditional logic.
 * Mimics real ISO consultant flow aligned with ISO/IEC 27001.
 */

class QueueManager {
  constructor() {
    this.queue = [];
    this.completed = [];
  }

  addUnique(items) {
    items.forEach(item => {
      if (!this.queue.includes(item) && !this.completed.includes(item)) {
        this.queue.push(item);
      }
    });
  }

  remove(item) {
    this.queue = this.queue.filter(q => q !== item);
  }

  markCompleted(item) {
    if (this.queue.includes(item)) {
      this.remove(item);
      this.completed.push(item);
    }
  }

  getNext() {
    return this.queue[0] || null;
  }

  getStatus() {
    return {
      pending: this.queue.length,
      completed: this.completed.length,
      total: this.queue.length + this.completed.length
    };
  }

  hasMore() {
    return this.queue.length > 0;
  }
}

class AdaptiveEngine {
  constructor(options = {}) {
    this.options = {
      mode: 'detailed',
      riskThreshold: 15,
      ...options
    };

    this.answers = {};
    this.queueManager = new QueueManager();
    this.riskScore = 0;
    this.metadata = null;
    this.currentQuestion = null;
    this.history = [];
    this.triggeredBlocks = new Set();
    this.metrics = {
      questionsAsked: 0,
      skippedQuestions: 0,
      triggeredQuestions: 0
    };

    this.debugMode = options.debug || false;
  }

  /**
   * Load metadata from JSON file
   * @param {Object} data - ISO metadata
   */
  loadMetadata(data) {
    this.metadata = data;
    this._log('[loadMetadata] Loaded metadata with', Object.keys(data.questions).length, 'questions');
    return this.metadata;
  }

  /**
   * Initialize flow based on mode (quick/detailed)
   * @param {string} mode - 'quick' or 'detailed'
   */
  initializeFlow(mode = null) {
    this.options.mode = mode || this.options.mode;
    this.answers = {};
    this.queueManager = new QueueManager();
    this.riskScore = 0;
    this.currentQuestion = null;
    this.history = [];
    this.triggeredBlocks = new Set();

    const blocksToLoad = this._getBlocksForMode(this.options.mode);
    this._loadBlocksToQueue(blocksToLoad);
    
    this._log('[initializeFlow] Mode:', this.options.mode, 'Queue length:', this.queueManager.queue.length);
  }

  /**
   * Get blocks for mode
   */
  _getBlocksForMode(mode) {
    if (mode === 'quick') {
      return ['base_block'];
    }
    return Object.keys(this.metadata.blocks);
  }

  /**
   * Load blocks into queue
   */
  _loadBlocksToQueue(blockIds) {
    blockIds.forEach(blockId => {
      const block = this.metadata.blocks[blockId];
      if (!block) return;

      if (!this._shouldShowBlock(block)) return;

      this.queueManager.addUnique(block.questions);
      this.triggeredBlocks.add(blockId);
      this._log('[loadBlocksToQueue] Added block:', blockId, 'Questions:', block.questions.length);
    });
  }

  /**
   * Check if block should be shown
   */
  _shouldShowBlock(block) {
    if (block.show_if && Object.keys(block.show_if).length > 0) {
      if (!this._evaluateCondition(block.show_if)) {
        this._log('[shouldShowBlock] Block filtered:', block.block_id);
        return false;
      }
    }
    if (block.skip_if && Object.keys(block.skip_if).length > 0) {
      if (this._evaluateCondition(block.skip_if)) {
        this._log('[shouldShowBlock] Block skipped:', block.block_id);
        return false;
      }
    }
    return true;
  }

  /**
   * Evaluate condition - supports AND/OR logic and simple conditions
   * @param {Object} condition - Condition object
   * @returns {boolean}
   */
  _evaluateCondition(condition) {
    if (!condition || typeof condition !== 'object') return true;
    if (Object.keys(condition).length === 0) return true;

    // Handle AND condition
    if (condition.AND) {
      return condition.AND.every(c => this._evaluateCondition(c));
    }

    // Handle OR condition
    if (condition.OR) {
      return condition.OR.some(c => this._evaluateCondition(c));
    }

    // Simple condition: { "q_cloud_usage": "Yes" }
    for (const [key, value] of Object.entries(condition)) {
      if (value && typeof value === 'object' && value.operator) {
        const actual = this.answers[key];
        switch (value.operator) {
          case 'equals': return actual === value.value;
          case 'not_equals': return actual !== value.value;
          case 'contains': return actual?.includes(value.value);
          case 'not_contains': !actual?.includes(value.value);
          case 'greater_than': return parseInt(actual) > parseInt(value.value);
          case 'less_than': return parseInt(actual) < parseInt(value.value);
          default: return actual === value.value;
        }
      }
      // Simple equality
      if (value === true) {
        // Check if answer is truthy
        return !!this.answers[key];
      }
      if (value === false) {
        return !this.answers[key];
      }
      return this.answers[key] === value;
    }
    return true;
  }

  /**
   * Check if question should be shown
   */
  _shouldShowQuestion(question) {
    if (!question) return false;

    // Check skip_if
    if (question.skip_if && Object.keys(question.skip_if).length > 0) {
      if (this._evaluateCondition(question.skip_if)) {
        this._log('[shouldShowQuestion] Skipped:', question.id);
        return false;
      }
    }

    // Check show_if
    if (question.show_if && Object.keys(question.show_if).length > 0) {
      if (!this._evaluateCondition(question.show_if)) {
        this._log('[shouldShowQuestion] Hidden:', question.id);
        return false;
      }
    }

    return true;
  }

  /**
   * Get next question from queue
   */
  getNextQuestion() {
    while (this.queueManager.queue.length > 0) {
      const nextId = this.queueManager.getNext();
      if (!nextId) return null;

      const question = this.metadata.questions[nextId];
      if (!question) {
        this.queueManager.markCompleted(nextId);
        continue;
      }

      if (!this._shouldShowQuestion(question)) {
        this.queueManager.markCompleted(nextId);
        this.metrics.skippedQuestions++;
        continue;
      }

      this.currentQuestion = question;
      this.metrics.questionsAsked++;
      return question;
    }
    return null;
  }

  /**
   * Process answer and update queue
   */
  processAnswer(questionId, answer) {
    const question = this.metadata.questions[questionId];
    if (!question) {
      throw new Error(`Unknown question: ${questionId}`);
    }

    // Store answer
    this.answers[questionId] = answer;
    this.queueManager.markCompleted(questionId);
    this.history.push({ questionId, answer, timestamp: Date.now() });

    // Update risk score
    this._updateRiskScore(question, answer);

    // Apply triggers
    this._applyTriggers(question, answer);

    // Check conditional blocks
    this._checkConditionalBlocks();

    // Inject risk-based blocks if needed
    this._injectRiskBasedBlocks();

    return {
      riskScore: this.riskScore,
      status: this.queueManager.getStatus(),
      isComplete: this.isComplete()
    };
  }

  /**
   * Update risk score
   */
  _updateRiskScore(question, answer) {
    let contribution = question.risk_weight || 0;
    const adjust = {
      'Yes': -1,
      'Yes - Comprehensive': -2,
      'Yes - Complete': -2,
      'No': contribution,
      'Yes - Documented': -1,
      'Yes - Formal': -1,
      'No': contribution,
      'Often': contribution,
      'Occasionally': 0,
      'Never': -1
    };
    
    if (answer && adjust[answer]) {
      contribution = adjust[answer];
    }
    
    this.riskScore = Math.max(0, this.riskScore + contribution);
    this._log('[updateRiskScore] New score:', this.riskScore, 'From:', questionId);
  }

  /**
   * Apply triggers from question
   */
  _applyTriggers(question, answer) {
    if (!question.triggers) return;

    for (const [triggerId, trigger] of Object.entries(question.triggers)) {
      if (trigger.operator === 'equals' && answer === trigger.value) {
        this._addBlock(triggerId);
      }
      if (trigger.operator === 'not_equals' && answer !== trigger.value) {
        this._addBlock(triggerId);
      }
      if (trigger.operator === 'contains' && answer?.includes(trigger.value)) {
        this._addBlock(triggerId);
      }
    }
  }

  /**
   * Add block dynamically
   */
  _addBlock(blockId) {
    const block = this.metadata.blocks[blockId];
    if (!block || this.triggeredBlocks.has(blockId)) return;

    if (!this._shouldShowBlock(block)) return;

    this.queueManager.addUnique(block.questions);
    this.triggeredBlocks.add(blockId);
    this.metrics.triggeredQuestions += block.questions.length;
    this._log('[addBlock] Added:', blockId);
  }

  /**
   * Check conditional blocks after each answer
   */
  _checkConditionalBlocks() {
    for (const [blockId, block] of Object.entries(this.metadata.blocks)) {
      if (this.triggeredBlocks.has(blockId)) continue;
      
      if (block.show_if && Object.keys(block.show_if).length > 0) {
        if (this._evaluateCondition(block.show_if)) {
          this._addBlock(blockId);
        }
      }
    }
  }

  /**
   * Inject risk-based blocks if threshold exceeded
   */
  _injectRiskBasedBlocks() {
    if (this.riskScore > this.options.riskThreshold) {
      this._addBlock('high_risk_block');
      this._addBlock('technical_security_block');
    }
  }

  /**
   * Check if assessment is complete
   */
  isComplete() {
    return !this.queueManager.hasMore();
  }

  /**
   * Get summary
   */
  getSummary() {
    return {
      questionsAsked: this.metrics.questionsAsked,
      skippedQuestions: this.metrics.skippedQuestions,
      triggeredQuestions: this.metrics.triggeredQuestions,
      riskScore: this.riskScore,
      riskLevel: this._getRiskLevel(),
      completedSections: this._getCompletedSections(),
      answersCount: Object.keys(this.answers).length
    };
  }

  /**
   * Get risk level
   */
  _getRiskLevel() {
    if (this.riskScore <= 5) return 'Low';
    if (this.riskScore <= 15) return 'Medium';
    if (this.riskScore <= 25) return 'High';
    return 'Critical';
  }

  /**
   * Get completed sections
   */
  _getCompletedSections() {
    const sections = new Set();
    Object.entries(this.answers).forEach(([qId]) => {
      const q = this.metadata.questions[qId];
      if (q?.clause) sections.add(q.clause);
    });
    return Array.from(sections);
  }

  /**
   * Export results
   */
  exportResults() {
    return {
      mode: this.options.mode,
      metadata: this.metadata?.metadata,
      answers: Object.entries(this.answers).map(([id, answer]) => {
        const q = this.metadata.questions[id];
        return { id, question: q?.question, answer, clause: q?.clause, section: q?.section };
      }),
      summary: this.getSummary(),
      generatedAt: new Date().toISOString()
    };
  }

  /**
   * Debug log
   */
  _log(...args) {
    if (this.debugMode) {
      console.log('[AdaptiveEngine]', ...args);
    }
  }

  /**
   * Enable/disable debug mode
   */
  setDebug(enable) {
    this.debugMode = enable;
  }
}

export default AdaptiveEngine;