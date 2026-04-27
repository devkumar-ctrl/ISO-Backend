import express from 'express'
import cors from 'cors'
import { v4 as uuidv4 } from 'uuid'
import dotenv from 'dotenv'
import OpenAI from 'openai'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
dotenv.config()

const app = express()
app.use(cors())
app.use(express.json())

const PORT = 3001

// Questions from demo files - SIMPLE
const ismsQuestions = [
  { id: 'q1', question: 'Organization Name', type: 'text' },
  { id: 'q2', question: 'Who is the CISO?', type: 'text' },
  { id: 'q3', question: 'Do you have Information Security Policy?', type: 'yesno' },
  { id: 'q4', question: 'Do you have Risk Assessment methodology?', type: 'yesno' },
  { id: 'q5', question: 'Do you have Business Continuity Plan?', type: 'yesno' },
  { id: 'q6', question: 'Is network traffic encrypted?', type: 'yesno' },
  { id: 'q7', question: 'Do you have backup testing?', type: 'yesno' },
  { id: 'q8', question: 'Do you have vendor security assessment?', type: 'yesno' },
  { id: 'q9', question: 'Is information classified?', type: 'yesno' },
  { id: 'q10', question: 'Do you have incident response plan?', type: 'yesno' }
]

const gapQuestions = [
  { id: 'g1', question: 'Clause 4 (Context) - Implemented?', type: 'yesno' },
  { id: 'g2', question: 'Clause 5 (Leadership) - Implemented?', type: 'yesno' },
  { id: 'g3', question: 'Clause 6 (Planning) - Implemented?', type: 'yesno' },
  { id: 'g4', question: 'Clause 7 (Support) - Implemented?', type: 'yesno' },
  { id: 'g5', question: 'Clause 8 (Operation) - Implemented?', type: 'yesno' },
  { id: 'g6', question: 'Clause 9 (Performance) - Implemented?', type: 'yesno' },
  { id: 'g7', question: 'Clause 10 (Improvement) - Implemented?', type: 'yesno' }
]

const riskQuestions = [
  { id: 'r1', question: 'Phishing Attack - status?', type: 'single', options: ['Mitigated', 'Partial', 'Not Mitigated'] },
  { id: 'r2', question: 'Ransomware - status?', type: 'single', options: ['Mitigated', 'Partial', 'Not Mitigated'] },
  { id: 'r3', question: 'Third-Party Breach - status?', type: 'single', options: ['Mitigated', 'Partial', 'Not Mitigated'] },
  { id: 'r4', question: 'Insider Threat - status?', type: 'single', options: ['Mitigated', 'Partial', 'Not Mitigated'] },
  { id: 'r5', question: 'DoS Attack - status?', type: 'single', options: ['Mitigated', 'Partial', 'Not Mitigated'] },
  { id: 'r6', question: 'Natural Disaster - status?', type: 'single', options: ['Mitigated', 'Partial', 'Not Mitigated'] }
]

const soaQuestions = [
  { id: 's1', question: 'A.5.1 Policies - Applicable?', type: 'yesno' },
  { id: 's2', question: 'A.5.2 Roles - Applicable?', type: 'yesno' },
  { id: 's3', question: 'A.6.1 Screening - Applicable?', type: 'yesno' },
  { id: 's4', question: 'A.7.1 Physical Security - Applicable?', type: 'yesno' },
  { id: 's5', question: 'A.8.1 Endpoint Hardening - Applicable?', type: 'yesno' },
  { id: 's6', question: 'A.9.2 User Access - Applicable?', type: 'yesno' },
  { id: 's7', question: 'A.12.2 Malware - Applicable?', type: 'yesno' },
  { id: 's8', question: 'A.13.1 Network Security - Applicable?', type: 'yesno' },
  { id: 's9', question: 'A.16.1 Incident - Applicable?', type: 'yesno' },
  { id: 's10', question: 'A.17.1 BC - Applicable?', type: 'yesno' }
]

// In-memory store
let assessmentData = {}

// 1. GET QUESTIONS
app.get('/api/questions/:docType', async (req, res) => {
  const { docType } = req.params
  let questions = []
  
  switch (docType) {
    case 'isms': questions = ismsQuestions; break
    case 'gap': questions = gapQuestions; break
    case 'risk': questions = riskQuestions; break
    case 'soa': questions = soaQuestions; break
    default: return res.status(400).json({ error: 'Invalid type' })
  }
  
  res.json({ success: true, questions })
})

// 2. SAVE ANSWERS
app.post('/api/answers/:docType', async (req, res) => {
  const { docType } = req.params
  const { answers } = req.body
  
  if (!assessmentData[docType]) {
    assessmentData[docType] = []
  }
  assessmentData[docType].push(answers)
  
  res.json({ success: true, saved: Object.keys(answers).length })
})

// 3. GENERATE DOCUMENT WITH AI
app.post('/api/generate/:docType', async (req, res) => {
  const { docType } = req.params
  const { apiKey } = req.body
  
  if (!apiKey) {
    return res.status(400).json({ error: 'OpenAI API key required' })
  }
  
  const ai = new OpenAI({ apiKey })
  const data = assessmentData[docType] || {}
  
  let prompt = ''
  switch (docType) {
    case 'isms':
      prompt = `Generate ISMS Policy document from: ${JSON.stringify(data)}. Include all ISO 27001 sections.`
      break
    case 'gap':
      prompt = `Generate Gap Assessment from: ${JSON.stringify(data)}. Show implemented vs gaps.`
      break
    case 'risk':
      prompt = `Generate Risk Assessment from: ${JSON.stringify(data)}. Include risk register.`
      break
    case 'soa':
      prompt = `Generate Statement of Applicability from: ${JSON.stringify(data)}. List 93 controls.`
      break
  }
  
  const completion = await ai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: prompt }]
  })
  
  res.json({ success: true, document: completion.choices[0].message.content })
})

// 4. START ASSESSMENT
app.post('/api/start', async (req, res) => {
  res.json({ 
    success: true,
    flow: ['isms', 'gap', 'risk', 'soa'],
    message: 'Ask questions -> Save answers -> Generate document'
  })
})

app.listen(PORT, () => {
  console.log(`ISO 27001 API running on http://localhost:${PORT}`)
})