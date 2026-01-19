// CySA+ Exam Prep Tool - Main Application

// State Management
const state = {
    currentSection: 'dashboard',
    currentLogScenario: null,
    currentCvssScenario: null,
    currentCveScenario: null,
    selectedLogAnswer: null,
    selectedCveAnswers: { vulnType: null, attackVector: null, mitigation: null },
    quiz: {
        active: false,
        questions: [],
        currentIndex: 0,
        score: 0,
        answers: [],
        timer: null,
        timeRemaining: 60,
        startTime: null,
        totalTime: 0
    },
    progress: {
        logCompleted: [],
        cvssCompleted: [],
        cveCompleted: [],
        totalAnswered: 0,
        totalCorrect: 0,
        currentStreak: 0,
        bestStreak: 0,
        recentActivity: []
    }
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    loadProgress();
    initNavigation();
    initLogAnalysis();
    initCvssCalculator();
    initCveAnalysis();
    initStudyMode();
    initQuizMode();
    updateDashboard();
});

// Load progress from localStorage
function loadProgress() {
    const saved = localStorage.getItem('cysaProgress');
    if (saved) {
        const parsed = JSON.parse(saved);
        state.progress = { ...state.progress, ...parsed };
    }
    updateHeaderStats();
}

// Save progress to localStorage
function saveProgress() {
    localStorage.setItem('cysaProgress', JSON.stringify(state.progress));
    updateHeaderStats();
    updateDashboard();
}

// Update header statistics
function updateHeaderStats() {
    const accuracy = state.progress.totalAnswered > 0
        ? Math.round((state.progress.totalCorrect / state.progress.totalAnswered) * 100)
        : 0;
    document.getElementById('overallScore').textContent = `Overall Score: ${accuracy}%`;
    document.getElementById('streakCounter').textContent = `Streak: ${state.progress.currentStreak}`;
}

// Navigation
function initNavigation() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const section = btn.dataset.section;
            navigateTo(section);
        });
    });

    document.querySelectorAll('[data-goto]').forEach(btn => {
        btn.addEventListener('click', () => {
            const section = btn.dataset.goto;
            navigateTo(section);
        });
    });

    document.getElementById('resetProgress').addEventListener('click', () => {
        if (confirm('Are you sure you want to reset all progress? This cannot be undone.')) {
            localStorage.removeItem('cysaProgress');
            state.progress = {
                logCompleted: [],
                cvssCompleted: [],
                cveCompleted: [],
                totalAnswered: 0,
                totalCorrect: 0,
                currentStreak: 0,
                bestStreak: 0,
                recentActivity: []
            };
            saveProgress();
            updateDashboard();
        }
    });
}

function navigateTo(section) {
    state.currentSection = section;

    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.section === section);
    });

    document.querySelectorAll('.section').forEach(sec => {
        sec.classList.toggle('active', sec.id === section);
    });
}

// Dashboard
function updateDashboard() {
    // Update progress rings
    const logPercent = Math.round((state.progress.logCompleted.length / logScenarios.length) * 100);
    const cvssPercent = Math.round((state.progress.cvssCompleted.length / cvssScenarios.length) * 100);
    const cvePercent = Math.round((state.progress.cveCompleted.length / cveScenarios.length) * 100);

    updateProgressRing('logProgress', logPercent);
    updateProgressRing('cvssProgress', cvssPercent);
    updateProgressRing('cveProgress', cvePercent);

    document.getElementById('logCompleted').textContent = state.progress.logCompleted.length;
    document.getElementById('cvssCompleted').textContent = state.progress.cvssCompleted.length;
    document.getElementById('cveCompleted').textContent = state.progress.cveCompleted.length;

    // Update stats
    document.getElementById('totalAnswered').textContent = state.progress.totalAnswered;
    document.getElementById('totalCorrect').textContent = state.progress.totalCorrect;
    const accuracy = state.progress.totalAnswered > 0
        ? Math.round((state.progress.totalCorrect / state.progress.totalAnswered) * 100)
        : 0;
    document.getElementById('accuracyRate').textContent = `${accuracy}%`;
    document.getElementById('bestStreak').textContent = state.progress.bestStreak;

    // Update activity log
    const activityLog = document.getElementById('activityLog');
    if (state.progress.recentActivity.length > 0) {
        activityLog.innerHTML = state.progress.recentActivity.slice(0, 10).map(activity => `
            <div class="activity-item">
                <span class="activity-icon ${activity.correct ? 'correct' : 'incorrect'}"></span>
                <span>${activity.text}</span>
            </div>
        `).join('');
    } else {
        activityLog.innerHTML = '<p class="no-activity">No recent activity. Start practicing!</p>';
    }
}

function updateProgressRing(id, percent) {
    const ring = document.getElementById(id);
    ring.style.background = `conic-gradient(#2563eb ${percent}%, #334155 ${percent}%)`;
    ring.querySelector('.progress-value').textContent = `${percent}%`;
}

// Log Analysis Module
function initLogAnalysis() {
    document.getElementById('newLogScenario').addEventListener('click', loadNewLogScenario);
    document.getElementById('submitLogAnalysis').addEventListener('click', submitLogAnalysis);
}

function loadNewLogScenario() {
    const difficulty = document.getElementById('logDifficulty').value;
    const type = document.getElementById('logType').value;

    let filteredScenarios = logScenarios.filter(s => {
        const diffMatch = difficulty === 'all' || s.difficulty === difficulty;
        const typeMatch = type === 'all' || s.type === type;
        return diffMatch && typeMatch;
    });

    if (filteredScenarios.length === 0) {
        filteredScenarios = logScenarios;
    }

    // Prioritize scenarios not yet completed
    const uncompletedScenarios = filteredScenarios.filter(s => !state.progress.logCompleted.includes(s.id));
    const availableScenarios = uncompletedScenarios.length > 0 ? uncompletedScenarios : filteredScenarios;

    state.currentLogScenario = availableScenarios[Math.floor(Math.random() * availableScenarios.length)];
    state.selectedLogAnswer = null;

    displayLogScenario();
}

function displayLogScenario() {
    const scenario = state.currentLogScenario;

    document.getElementById('logScenarioBadge').textContent = capitalize(scenario.difficulty);
    document.getElementById('logScenarioBadge').className = `scenario-badge ${scenario.difficulty}`;
    document.getElementById('logScenarioType').textContent = getLogTypeName(scenario.type);
    document.getElementById('logContent').textContent = scenario.log;

    // Display answer options
    const optionsContainer = document.getElementById('eventTypeOptions');
    const shuffledOptions = shuffleArray([...eventTypes]);

    optionsContainer.innerHTML = shuffledOptions.map(opt => `
        <button class="option-btn" data-answer="${opt.id}">${opt.label}</button>
    `).join('');

    optionsContainer.querySelectorAll('.option-btn').forEach(btn => {
        btn.addEventListener('click', () => selectLogAnswer(btn.dataset.answer));
    });

    document.getElementById('submitLogAnalysis').disabled = true;
    document.getElementById('logFeedback').style.display = 'none';
}

function selectLogAnswer(answer) {
    state.selectedLogAnswer = answer;

    document.querySelectorAll('#eventTypeOptions .option-btn').forEach(btn => {
        btn.classList.toggle('selected', btn.dataset.answer === answer);
    });

    document.getElementById('submitLogAnalysis').disabled = false;
}

function submitLogAnalysis() {
    const scenario = state.currentLogScenario;
    const isCorrect = state.selectedLogAnswer === scenario.correctAnswer;

    // Update progress
    state.progress.totalAnswered++;
    if (isCorrect) {
        state.progress.totalCorrect++;
        state.progress.currentStreak++;
        if (state.progress.currentStreak > state.progress.bestStreak) {
            state.progress.bestStreak = state.progress.currentStreak;
        }
        if (!state.progress.logCompleted.includes(scenario.id)) {
            state.progress.logCompleted.push(scenario.id);
        }
    } else {
        state.progress.currentStreak = 0;
    }

    state.progress.recentActivity.unshift({
        text: `Log Analysis: ${scenario.title} - ${isCorrect ? 'Correct' : 'Incorrect'}`,
        correct: isCorrect,
        timestamp: new Date().toISOString()
    });

    saveProgress();

    // Show correct/incorrect styling on options
    document.querySelectorAll('#eventTypeOptions .option-btn').forEach(btn => {
        if (btn.dataset.answer === scenario.correctAnswer) {
            btn.classList.add('correct');
        } else if (btn.dataset.answer === state.selectedLogAnswer && !isCorrect) {
            btn.classList.add('incorrect');
        }
        btn.disabled = true;
    });

    // Display feedback
    const feedback = document.getElementById('logFeedback');
    const correctLabel = eventTypes.find(e => e.id === scenario.correctAnswer).label;

    feedback.className = `feedback-panel ${isCorrect ? 'correct' : 'incorrect'}`;
    feedback.innerHTML = `
        <div class="feedback-header">
            <span class="feedback-icon">${isCorrect ? '✓' : '✗'}</span>
            <span class="feedback-title ${isCorrect ? 'correct' : 'incorrect'}">
                ${isCorrect ? 'Correct!' : 'Incorrect'}
            </span>
        </div>
        <div class="feedback-content">
            <p><strong>Answer:</strong> ${correctLabel}</p>
            <p><strong>Explanation:</strong> ${scenario.explanation}</p>
            <p><strong>Key Indicators:</strong></p>
            <ul>
                ${scenario.indicators.map(i => `<li>${i}</li>`).join('')}
            </ul>
        </div>
    `;
    feedback.style.display = 'block';

    document.getElementById('submitLogAnalysis').disabled = true;
}

// CVSS Calculator Module
function initCvssCalculator() {
    document.getElementById('cvssVersion').addEventListener('change', toggleCvssVersion);
    document.getElementById('cvssMode').addEventListener('change', toggleCvssMode);
    document.getElementById('newCvssScenario').addEventListener('click', loadNewCvssScenario);
    document.getElementById('submitCvss').addEventListener('click', submitCvssScore);

    // Add listeners for score calculation
    const metricSelects = document.querySelectorAll('#cvssMetrics31 select, #cvssMetrics40 select');
    metricSelects.forEach(select => {
        select.addEventListener('change', calculateCvssScore);
    });
}

function toggleCvssVersion() {
    const version = document.getElementById('cvssVersion').value;
    document.getElementById('cvssMetrics31').style.display = version === '3.1' ? 'block' : 'none';
    document.getElementById('cvssMetrics40').style.display = version === '4.0' ? 'block' : 'none';
    resetCvssForm();
}

function toggleCvssMode() {
    const mode = document.getElementById('cvssMode').value;
    const vulnDesc = document.getElementById('vulnDescription');

    if (mode === 'calculator') {
        vulnDesc.innerHTML = `
            <h3>Free Calculator Mode</h3>
            <p>Use this mode to practice calculating CVSS scores for any vulnerability. Select the appropriate metrics below and see the calculated score.</p>
        `;
        state.currentCvssScenario = null;
        document.getElementById('submitCvss').textContent = 'Calculate Score';
    } else {
        vulnDesc.innerHTML = `
            <h3>Vulnerability Scenario</h3>
            <p id="vulnText">Click "New Vulnerability" to start a CVSS scoring exercise...</p>
        `;
        document.getElementById('submitCvss').textContent = 'Submit Score';
    }
    resetCvssForm();
}

function resetCvssForm() {
    document.querySelectorAll('#cvssMetrics31 select, #cvssMetrics40 select').forEach(select => {
        select.value = '';
    });
    document.getElementById('userCvssScore').textContent = '--';
    document.getElementById('userSeverity').textContent = '--';
    document.getElementById('userSeverity').className = 'severity-badge';
    document.getElementById('cvssFeedback').style.display = 'none';
}

function loadNewCvssScenario() {
    const version = document.getElementById('cvssVersion').value;
    const availableScenarios = cvssScenarios.filter(s => s.version === version);

    // Prioritize uncompleted scenarios
    const uncompleted = availableScenarios.filter(s => !state.progress.cvssCompleted.includes(s.id));
    const pool = uncompleted.length > 0 ? uncompleted : availableScenarios;

    state.currentCvssScenario = pool[Math.floor(Math.random() * pool.length)];

    document.getElementById('vulnText').textContent = state.currentCvssScenario.description;
    document.getElementById('cvssMode').value = 'practice';
    document.getElementById('submitCvss').textContent = 'Submit Score';

    resetCvssForm();
}

function calculateCvssScore() {
    const version = document.getElementById('cvssVersion').value;
    let score, severity;

    if (version === '3.1') {
        score = calculateCvss31Score();
    } else {
        score = calculateCvss40Score();
    }

    if (score !== null) {
        document.getElementById('userCvssScore').textContent = score.toFixed(1);
        severity = getSeverityFromScore(score);
        document.getElementById('userSeverity').textContent = severity;
        document.getElementById('userSeverity').className = `severity-badge ${severity.toLowerCase()}`;
    }

    return score;
}

function calculateCvss31Score() {
    const av = document.getElementById('av31').value;
    const ac = document.getElementById('ac31').value;
    const pr = document.getElementById('pr31').value;
    const ui = document.getElementById('ui31').value;
    const s = document.getElementById('s31').value;
    const c = document.getElementById('c31').value;
    const i = document.getElementById('i31').value;
    const a = document.getElementById('a31').value;

    if (!av || !ac || !pr || !ui || !s || !c || !i || !a) {
        return null;
    }

    // CVSS 3.1 Metric Values
    const avValues = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
    const acValues = { L: 0.77, H: 0.44 };
    const prValues = {
        U: { N: 0.85, L: 0.62, H: 0.27 },
        C: { N: 0.85, L: 0.68, H: 0.50 }
    };
    const uiValues = { N: 0.85, R: 0.62 };
    const ciaValues = { N: 0, L: 0.22, H: 0.56 };

    const exploitability = 8.22 * avValues[av] * acValues[ac] * prValues[s][pr] * uiValues[ui];

    const impactBase = 1 - ((1 - ciaValues[c]) * (1 - ciaValues[i]) * (1 - ciaValues[a]));

    let impact;
    if (s === 'U') {
        impact = 6.42 * impactBase;
    } else {
        impact = 7.52 * (impactBase - 0.029) - 3.25 * Math.pow(impactBase - 0.02, 15);
    }

    if (impact <= 0) {
        return 0;
    }

    let score;
    if (s === 'U') {
        score = Math.min(exploitability + impact, 10);
    } else {
        score = Math.min(1.08 * (exploitability + impact), 10);
    }

    return Math.ceil(score * 10) / 10;
}

function calculateCvss40Score() {
    // CVSS 4.0 simplified calculation (actual 4.0 is lookup table based)
    const av = document.getElementById('av40').value;
    const ac = document.getElementById('ac40').value;
    const at = document.getElementById('at40').value;
    const pr = document.getElementById('pr40').value;
    const ui = document.getElementById('ui40').value;
    const vc = document.getElementById('vc40').value;
    const vi = document.getElementById('vi40').value;
    const va = document.getElementById('va40').value;
    const sc = document.getElementById('sc40').value;
    const si = document.getElementById('si40').value;
    const sa = document.getElementById('sa40').value;

    if (!av || !ac || !at || !pr || !ui || !vc || !vi || !va || !sc || !si || !sa) {
        return null;
    }

    // Simplified scoring (CVSS 4.0 uses complex lookup tables in practice)
    const avScores = { N: 1.0, A: 0.8, L: 0.6, P: 0.3 };
    const acScores = { L: 1.0, H: 0.5 };
    const atScores = { N: 1.0, P: 0.7 };
    const prScores = { N: 1.0, L: 0.7, H: 0.4 };
    const uiScores = { N: 1.0, P: 0.8, A: 0.6 };
    const impactScores = { N: 0, L: 0.3, H: 1.0 };

    const exploitability = avScores[av] * acScores[ac] * atScores[at] * prScores[pr] * uiScores[ui];
    const vulnImpact = (impactScores[vc] + impactScores[vi] + impactScores[va]) / 3;
    const subImpact = (impactScores[sc] + impactScores[si] + impactScores[sa]) / 3;

    const totalImpact = Math.max(vulnImpact, vulnImpact + subImpact * 0.5);
    let score = 10 * exploitability * totalImpact;

    return Math.min(Math.ceil(score * 10) / 10, 10);
}

function getSeverityFromScore(score) {
    if (score === 0) return 'None';
    if (score < 4) return 'Low';
    if (score < 7) return 'Medium';
    if (score < 9) return 'High';
    return 'Critical';
}

function submitCvssScore() {
    const mode = document.getElementById('cvssMode').value;
    const userScore = calculateCvssScore();

    if (userScore === null) {
        alert('Please select all metrics before submitting.');
        return;
    }

    if (mode === 'calculator' || !state.currentCvssScenario) {
        // Just show the calculated score
        const feedback = document.getElementById('cvssFeedback');
        feedback.className = 'feedback-panel correct';
        feedback.innerHTML = `
            <div class="feedback-header">
                <span class="feedback-icon">✓</span>
                <span class="feedback-title correct">Score Calculated</span>
            </div>
            <div class="feedback-content">
                <p><strong>Your CVSS Score:</strong> ${userScore.toFixed(1)} (${getSeverityFromScore(userScore)})</p>
            </div>
        `;
        feedback.style.display = 'block';
        return;
    }

    // Practice mode - compare against correct answer
    const scenario = state.currentCvssScenario;
    const correctScore = scenario.correctScore;
    const scoreDiff = Math.abs(userScore - correctScore);
    const isCorrect = scoreDiff <= 0.5; // Allow 0.5 tolerance

    state.progress.totalAnswered++;
    if (isCorrect) {
        state.progress.totalCorrect++;
        state.progress.currentStreak++;
        if (state.progress.currentStreak > state.progress.bestStreak) {
            state.progress.bestStreak = state.progress.currentStreak;
        }
        if (!state.progress.cvssCompleted.includes(scenario.id)) {
            state.progress.cvssCompleted.push(scenario.id);
        }
    } else {
        state.progress.currentStreak = 0;
    }

    state.progress.recentActivity.unshift({
        text: `CVSS Scoring: ${userScore.toFixed(1)} vs ${correctScore} - ${isCorrect ? 'Correct' : 'Incorrect'}`,
        correct: isCorrect,
        timestamp: new Date().toISOString()
    });

    saveProgress();

    // Display feedback
    const feedback = document.getElementById('cvssFeedback');
    feedback.className = `feedback-panel ${isCorrect ? 'correct' : 'incorrect'}`;

    let metricsHtml = '';
    for (const [metric, explanation] of Object.entries(scenario.explanation)) {
        const metricName = getMetricName(metric);
        const correctValue = scenario.correctMetrics[metric];
        metricsHtml += `<p><strong>${metricName} (${correctValue}):</strong> ${explanation}</p>`;
    }

    feedback.innerHTML = `
        <div class="feedback-header">
            <span class="feedback-icon">${isCorrect ? '✓' : '✗'}</span>
            <span class="feedback-title ${isCorrect ? 'correct' : 'incorrect'}">
                ${isCorrect ? 'Correct!' : 'Incorrect'}
            </span>
        </div>
        <div class="feedback-content">
            <p><strong>Your Score:</strong> ${userScore.toFixed(1)} (${getSeverityFromScore(userScore)})</p>
            <p><strong>Correct Score:</strong> ${correctScore} (${scenario.severity})</p>
            <h4>Metric Explanations:</h4>
            ${metricsHtml}
        </div>
    `;
    feedback.style.display = 'block';
}

function getMetricName(code) {
    const names = {
        AV: 'Attack Vector', AC: 'Attack Complexity', PR: 'Privileges Required',
        UI: 'User Interaction', S: 'Scope', C: 'Confidentiality', I: 'Integrity', A: 'Availability'
    };
    return names[code] || code;
}

// CVE Analysis Module
function initCveAnalysis() {
    document.getElementById('newCveScenario').addEventListener('click', loadNewCveScenario);
    document.getElementById('submitCveAnalysis').addEventListener('click', submitCveAnalysis);
}

function loadNewCveScenario() {
    const difficulty = document.getElementById('cveDifficulty').value;
    const category = document.getElementById('cveCategory').value;

    let filtered = cveScenarios.filter(s => {
        const diffMatch = difficulty === 'all' || s.difficulty === difficulty;
        const catMatch = category === 'all' || s.category === category;
        return diffMatch && catMatch;
    });

    if (filtered.length === 0) filtered = cveScenarios;

    const uncompleted = filtered.filter(s => !state.progress.cveCompleted.includes(s.id));
    const pool = uncompleted.length > 0 ? uncompleted : filtered;

    state.currentCveScenario = pool[Math.floor(Math.random() * pool.length)];
    state.selectedCveAnswers = { vulnType: null, attackVector: null, mitigation: null };

    displayCveScenario();
}

function displayCveScenario() {
    const cve = state.currentCveScenario;

    document.getElementById('cveId').textContent = cve.cveId;
    document.getElementById('cveSeverityBadge').textContent = cve.severity;
    document.getElementById('cveSeverityBadge').className = `severity-badge ${cve.severity.toLowerCase()}`;
    document.getElementById('cveDescription').textContent = cve.description;
    document.getElementById('cvePublished').textContent = cve.published;
    document.getElementById('cveCvssScore').textContent = cve.cvssScore;
    document.getElementById('cveAffected').textContent = cve.affectedProducts;
    document.getElementById('cveMeta').style.display = 'block';

    // Populate question options
    displayCveOptions('vulnTypeOptions', vulnTypeOptions, 'vulnType');
    displayCveOptions('attackVectorOptions', attackVectorOptions, 'attackVector');
    displayCveOptions('mitigationOptions', mitigationOptions, 'mitigation');

    document.getElementById('cveQuestions').style.display = 'block';
    document.getElementById('submitCveAnalysis').disabled = true;
    document.getElementById('cveFeedback').style.display = 'none';
}

function displayCveOptions(containerId, options, questionType) {
    const container = document.getElementById(containerId);
    const shuffled = shuffleArray([...options]);

    container.innerHTML = shuffled.map(opt => `
        <button class="option-btn" data-question="${questionType}" data-answer="${opt.id}">${opt.label}</button>
    `).join('');

    container.querySelectorAll('.option-btn').forEach(btn => {
        btn.addEventListener('click', () => selectCveAnswer(questionType, btn.dataset.answer));
    });
}

function selectCveAnswer(questionType, answer) {
    state.selectedCveAnswers[questionType] = answer;

    document.querySelectorAll(`[data-question="${questionType}"]`).forEach(btn => {
        btn.classList.toggle('selected', btn.dataset.answer === answer);
    });

    // Enable submit if all questions answered
    const allAnswered = state.selectedCveAnswers.vulnType &&
                        state.selectedCveAnswers.attackVector &&
                        state.selectedCveAnswers.mitigation;
    document.getElementById('submitCveAnalysis').disabled = !allAnswered;
}

function submitCveAnalysis() {
    const cve = state.currentCveScenario;
    const answers = state.selectedCveAnswers;

    const vulnCorrect = answers.vulnType === cve.questions.vulnType.correct;
    const vectorCorrect = answers.attackVector === cve.questions.attackVector.correct;
    const mitigationCorrect = answers.mitigation === cve.questions.mitigation.correct;

    const correctCount = [vulnCorrect, vectorCorrect, mitigationCorrect].filter(Boolean).length;
    const isFullyCorrect = correctCount === 3;

    state.progress.totalAnswered += 3;
    state.progress.totalCorrect += correctCount;

    if (isFullyCorrect) {
        state.progress.currentStreak++;
        if (state.progress.currentStreak > state.progress.bestStreak) {
            state.progress.bestStreak = state.progress.currentStreak;
        }
        if (!state.progress.cveCompleted.includes(cve.id)) {
            state.progress.cveCompleted.push(cve.id);
        }
    } else {
        state.progress.currentStreak = 0;
    }

    state.progress.recentActivity.unshift({
        text: `CVE Analysis: ${cve.cveId} - ${correctCount}/3 correct`,
        correct: isFullyCorrect,
        timestamp: new Date().toISOString()
    });

    saveProgress();

    // Show correct/incorrect on options
    ['vulnType', 'attackVector', 'mitigation'].forEach(q => {
        const correct = cve.questions[q].correct;
        document.querySelectorAll(`[data-question="${q}"]`).forEach(btn => {
            if (btn.dataset.answer === correct) {
                btn.classList.add('correct');
            } else if (btn.dataset.answer === answers[q] && answers[q] !== correct) {
                btn.classList.add('incorrect');
            }
            btn.disabled = true;
        });
    });

    // Display feedback
    const feedback = document.getElementById('cveFeedback');
    feedback.className = `feedback-panel ${isFullyCorrect ? 'correct' : 'incorrect'}`;

    feedback.innerHTML = `
        <div class="feedback-header">
            <span class="feedback-icon">${isFullyCorrect ? '✓' : '✗'}</span>
            <span class="feedback-title ${isFullyCorrect ? 'correct' : 'incorrect'}">
                ${correctCount}/3 Correct
            </span>
        </div>
        <div class="feedback-content">
            <p><strong>Vulnerability Type:</strong> ${vulnCorrect ? '✓' : '✗'} ${cve.questions.vulnType.explanation}</p>
            <p><strong>Attack Vector:</strong> ${vectorCorrect ? '✓' : '✗'} ${cve.questions.attackVector.explanation}</p>
            <p><strong>Mitigation:</strong> ${mitigationCorrect ? '✓' : '✗'} ${cve.questions.mitigation.explanation}</p>
            <p><strong>Full Mitigation Details:</strong> ${cve.mitigationExplanation}</p>
        </div>
    `;
    feedback.style.display = 'block';

    document.getElementById('submitCveAnalysis').disabled = true;
}

// Study Mode
function initStudyMode() {
    document.querySelectorAll('.study-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const study = tab.dataset.study;

            document.querySelectorAll('.study-tab').forEach(t => {
                t.classList.toggle('active', t.dataset.study === study);
            });

            document.querySelectorAll('.study-panel').forEach(p => {
                p.classList.toggle('active', p.id === study);
            });
        });
    });
}

// Quiz Mode
function initQuizMode() {
    document.getElementById('startQuiz').addEventListener('click', startQuiz);
    document.getElementById('submitQuizAnswer').addEventListener('click', submitQuizAnswer);
    document.getElementById('skipQuestion').addEventListener('click', skipQuestion);
    document.getElementById('retakeQuiz').addEventListener('click', () => {
        document.getElementById('quizSetup').style.display = 'block';
        document.getElementById('quizResults').style.display = 'none';
    });
    document.getElementById('reviewQuiz').addEventListener('click', reviewQuizAnswers);
}

function startQuiz() {
    const questionCount = parseInt(document.getElementById('quizQuestionCount').value);
    const timeLimit = parseInt(document.getElementById('quizTimeLimit').value);
    const difficulty = document.getElementById('quizDifficulty').value;

    const includeLog = document.getElementById('includeLog').checked;
    const includeCvss = document.getElementById('includeCvss').checked;
    const includeCve = document.getElementById('includeCve').checked;

    if (!includeLog && !includeCvss && !includeCve) {
        alert('Please select at least one question type.');
        return;
    }

    // Build question pool
    const questions = [];

    if (includeLog) {
        let logs = logScenarios;
        if (difficulty !== 'all') {
            logs = logs.filter(s => s.difficulty === difficulty);
        }
        logs.forEach(s => questions.push({ type: 'log', data: s }));
    }

    if (includeCvss) {
        cvssScenarios.forEach(s => questions.push({ type: 'cvss', data: s }));
    }

    if (includeCve) {
        let cves = cveScenarios;
        if (difficulty !== 'all') {
            cves = cves.filter(s => s.difficulty === difficulty);
        }
        cves.forEach(s => questions.push({ type: 'cve', data: s }));
    }

    // Shuffle and select questions
    const shuffled = shuffleArray(questions);
    state.quiz = {
        active: true,
        questions: shuffled.slice(0, Math.min(questionCount, shuffled.length)),
        currentIndex: 0,
        score: 0,
        answers: [],
        timer: null,
        timePerQuestion: timeLimit,
        timeRemaining: timeLimit,
        startTime: Date.now(),
        totalTime: 0
    };

    document.getElementById('quizSetup').style.display = 'none';
    document.getElementById('quizActive').style.display = 'block';
    document.getElementById('quizResults').style.display = 'none';

    document.getElementById('totalQuestions').textContent = state.quiz.questions.length;

    displayQuizQuestion();
}

function displayQuizQuestion() {
    const quiz = state.quiz;
    const question = quiz.questions[quiz.currentIndex];

    document.getElementById('currentQuestion').textContent = quiz.currentIndex + 1;
    document.getElementById('quizScore').textContent = quiz.score;
    document.getElementById('quizProgressBar').style.width =
        `${((quiz.currentIndex) / quiz.questions.length) * 100}%`;

    const container = document.getElementById('quizQuestion');

    if (question.type === 'log') {
        displayQuizLogQuestion(container, question.data);
    } else if (question.type === 'cvss') {
        displayQuizCvssQuestion(container, question.data);
    } else if (question.type === 'cve') {
        displayQuizCveQuestion(container, question.data);
    }

    // Start timer
    quiz.timeRemaining = quiz.timePerQuestion;
    updateQuizTimer();
    clearInterval(quiz.timer);
    quiz.timer = setInterval(() => {
        quiz.timeRemaining--;
        updateQuizTimer();
        if (quiz.timeRemaining <= 0) {
            clearInterval(quiz.timer);
            skipQuestion();
        }
    }, 1000);

    document.getElementById('submitQuizAnswer').disabled = true;
}

function displayQuizLogQuestion(container, scenario) {
    const shuffledOptions = shuffleArray([...eventTypes]).slice(0, 6);
    if (!shuffledOptions.find(o => o.id === scenario.correctAnswer)) {
        shuffledOptions[0] = eventTypes.find(o => o.id === scenario.correctAnswer);
    }

    container.innerHTML = `
        <div class="scenario-header">
            <span class="scenario-badge ${scenario.difficulty}">${capitalize(scenario.difficulty)}</span>
            <span class="scenario-type">Log Analysis</span>
        </div>
        <div class="log-display">
            <pre>${scenario.log}</pre>
        </div>
        <div class="question-block">
            <h4>What type of security event is occurring?</h4>
            <div class="options-grid">
                ${shuffleArray(shuffledOptions).map(opt => `
                    <button class="option-btn" data-answer="${opt.id}">${opt.label}</button>
                `).join('')}
            </div>
        </div>
    `;

    container.querySelectorAll('.option-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            container.querySelectorAll('.option-btn').forEach(b => b.classList.remove('selected'));
            btn.classList.add('selected');
            state.quiz.currentAnswer = btn.dataset.answer;
            document.getElementById('submitQuizAnswer').disabled = false;
        });
    });
}

function displayQuizCvssQuestion(container, scenario) {
    container.innerHTML = `
        <div class="scenario-header">
            <span class="scenario-badge intermediate">CVSS</span>
            <span class="scenario-type">Score Estimation</span>
        </div>
        <div class="vulnerability-description">
            <p>${scenario.description}</p>
        </div>
        <div class="question-block">
            <h4>What is the approximate CVSS ${scenario.version} base score?</h4>
            <div class="options-grid">
                ${generateScoreOptions(scenario.correctScore).map(score => `
                    <button class="option-btn" data-answer="${score}">${score} (${getSeverityFromScore(score)})</button>
                `).join('')}
            </div>
        </div>
    `;

    container.querySelectorAll('.option-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            container.querySelectorAll('.option-btn').forEach(b => b.classList.remove('selected'));
            btn.classList.add('selected');
            state.quiz.currentAnswer = parseFloat(btn.dataset.answer);
            document.getElementById('submitQuizAnswer').disabled = false;
        });
    });
}

function displayQuizCveQuestion(container, cve) {
    const questionTypes = ['vulnType', 'attackVector', 'mitigation'];
    const qType = questionTypes[Math.floor(Math.random() * questionTypes.length)];

    let questionText, options, correctAnswer;

    if (qType === 'vulnType') {
        questionText = 'What type of vulnerability is this?';
        options = shuffleArray([...vulnTypeOptions]).slice(0, 4);
        correctAnswer = cve.questions.vulnType.correct;
        if (!options.find(o => o.id === correctAnswer)) {
            options[0] = vulnTypeOptions.find(o => o.id === correctAnswer);
        }
    } else if (qType === 'attackVector') {
        questionText = 'What is the primary attack vector?';
        options = attackVectorOptions;
        correctAnswer = cve.questions.attackVector.correct;
    } else {
        questionText = 'What is the recommended mitigation?';
        options = shuffleArray([...mitigationOptions]).slice(0, 4);
        correctAnswer = cve.questions.mitigation.correct;
        if (!options.find(o => o.id === correctAnswer)) {
            options[0] = mitigationOptions.find(o => o.id === correctAnswer);
        }
    }

    state.quiz.currentQuestionType = qType;

    container.innerHTML = `
        <div class="scenario-header">
            <span class="severity-badge ${cve.severity.toLowerCase()}">${cve.severity}</span>
            <span class="scenario-type">CVE Analysis</span>
        </div>
        <div class="cve-details">
            <h3>${cve.cveId} - ${cve.name}</h3>
            <p>${cve.description}</p>
        </div>
        <div class="question-block">
            <h4>${questionText}</h4>
            <div class="options-grid">
                ${shuffleArray(options).map(opt => `
                    <button class="option-btn" data-answer="${opt.id}">${opt.label}</button>
                `).join('')}
            </div>
        </div>
    `;

    container.querySelectorAll('.option-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            container.querySelectorAll('.option-btn').forEach(b => b.classList.remove('selected'));
            btn.classList.add('selected');
            state.quiz.currentAnswer = btn.dataset.answer;
            document.getElementById('submitQuizAnswer').disabled = false;
        });
    });
}

function generateScoreOptions(correctScore) {
    const options = new Set([correctScore]);

    // Add nearby incorrect options
    const offsets = [-2.5, -1.5, -0.8, 0.8, 1.5, 2.5];
    for (const offset of offsets) {
        const score = Math.round((correctScore + offset) * 10) / 10;
        if (score >= 0 && score <= 10) {
            options.add(score);
        }
        if (options.size >= 4) break;
    }

    return shuffleArray([...options]).slice(0, 4);
}

function updateQuizTimer() {
    const timerEl = document.getElementById('quizTimer');
    timerEl.textContent = state.quiz.timeRemaining;

    const timerContainer = timerEl.parentElement;
    timerContainer.classList.remove('warning', 'danger');

    if (state.quiz.timeRemaining <= 10) {
        timerContainer.classList.add('danger');
    } else if (state.quiz.timeRemaining <= 20) {
        timerContainer.classList.add('warning');
    }
}

function submitQuizAnswer() {
    clearInterval(state.quiz.timer);

    const quiz = state.quiz;
    const question = quiz.questions[quiz.currentIndex];
    let isCorrect = false;

    if (question.type === 'log') {
        isCorrect = quiz.currentAnswer === question.data.correctAnswer;
    } else if (question.type === 'cvss') {
        isCorrect = Math.abs(quiz.currentAnswer - question.data.correctScore) <= 1;
    } else if (question.type === 'cve') {
        const qType = quiz.currentQuestionType;
        isCorrect = quiz.currentAnswer === question.data.questions[qType].correct;
    }

    if (isCorrect) {
        quiz.score++;
    }

    quiz.answers.push({
        question: question,
        userAnswer: quiz.currentAnswer,
        correct: isCorrect,
        timeSpent: quiz.timePerQuestion - quiz.timeRemaining,
        questionType: question.type === 'cve' ? quiz.currentQuestionType : null
    });

    quiz.totalTime += quiz.timePerQuestion - quiz.timeRemaining;

    // Show visual feedback
    const container = document.getElementById('quizQuestion');
    container.querySelectorAll('.option-btn').forEach(btn => {
        let correctAnswer;
        if (question.type === 'log') {
            correctAnswer = question.data.correctAnswer;
        } else if (question.type === 'cvss') {
            correctAnswer = question.data.correctScore.toString();
        } else {
            correctAnswer = question.data.questions[quiz.currentQuestionType].correct;
        }

        if (btn.dataset.answer === correctAnswer || btn.dataset.answer === correctAnswer.toString()) {
            btn.classList.add('correct');
        } else if (btn.classList.contains('selected') && !isCorrect) {
            btn.classList.add('incorrect');
        }
    });

    setTimeout(() => {
        quiz.currentIndex++;
        if (quiz.currentIndex < quiz.questions.length) {
            displayQuizQuestion();
        } else {
            endQuiz();
        }
    }, 1500);
}

function skipQuestion() {
    clearInterval(state.quiz.timer);

    const quiz = state.quiz;
    const question = quiz.questions[quiz.currentIndex];

    quiz.answers.push({
        question: question,
        userAnswer: null,
        correct: false,
        timeSpent: quiz.timePerQuestion,
        questionType: question.type === 'cve' ? quiz.currentQuestionType : null
    });

    quiz.totalTime += quiz.timePerQuestion;
    quiz.currentIndex++;

    if (quiz.currentIndex < quiz.questions.length) {
        displayQuizQuestion();
    } else {
        endQuiz();
    }
}

function endQuiz() {
    state.quiz.active = false;

    document.getElementById('quizActive').style.display = 'none';
    document.getElementById('quizResults').style.display = 'block';

    const quiz = state.quiz;
    const percentage = Math.round((quiz.score / quiz.questions.length) * 100);
    const avgTime = Math.round(quiz.totalTime / quiz.questions.length);

    document.getElementById('finalScore').textContent = `${percentage}%`;
    document.getElementById('correctCount').textContent = `${quiz.score}/${quiz.questions.length}`;
    document.getElementById('avgTime').textContent = `${avgTime}s`;

    // Update progress
    state.progress.totalAnswered += quiz.questions.length;
    state.progress.totalCorrect += quiz.score;

    state.progress.recentActivity.unshift({
        text: `Quiz: ${quiz.score}/${quiz.questions.length} (${percentage}%)`,
        correct: percentage >= 70,
        timestamp: new Date().toISOString()
    });

    saveProgress();

    // Display breakdown
    const breakdown = document.getElementById('resultsBreakdown');
    breakdown.innerHTML = quiz.answers.map((a, i) => {
        let questionText;
        if (a.question.type === 'log') {
            questionText = `Log Analysis: ${a.question.data.title}`;
        } else if (a.question.type === 'cvss') {
            questionText = `CVSS: ${a.question.data.description.substring(0, 50)}...`;
        } else {
            questionText = `CVE: ${a.question.data.cveId}`;
        }

        return `
            <div class="breakdown-item">
                <span class="breakdown-icon">${a.correct ? '✓' : '✗'}</span>
                <span class="breakdown-text">Q${i + 1}: ${questionText}</span>
            </div>
        `;
    }).join('');
}

function reviewQuizAnswers() {
    state.quiz.reviewIndex = 0;
    showReviewModal();
}

function showReviewModal() {
    const modal = document.getElementById('reviewModal');
    modal.style.display = 'flex';

    document.getElementById('reviewTotalQ').textContent = state.quiz.answers.length;

    // Add event listeners for modal controls
    document.getElementById('closeReviewModal').onclick = closeReviewModal;
    document.getElementById('closeReviewBtn').onclick = closeReviewModal;
    document.getElementById('prevReviewQuestion').onclick = () => navigateReview(-1);
    document.getElementById('nextReviewQuestion').onclick = () => navigateReview(1);

    // Close modal on background click
    modal.onclick = (e) => {
        if (e.target === modal) closeReviewModal();
    };

    // Close on Escape key
    document.addEventListener('keydown', handleReviewKeydown);

    displayReviewQuestion();
}

function handleReviewKeydown(e) {
    if (e.key === 'Escape') {
        closeReviewModal();
    } else if (e.key === 'ArrowLeft') {
        navigateReview(-1);
    } else if (e.key === 'ArrowRight') {
        navigateReview(1);
    }
}

function closeReviewModal() {
    document.getElementById('reviewModal').style.display = 'none';
    document.removeEventListener('keydown', handleReviewKeydown);
}

function navigateReview(direction) {
    const newIndex = state.quiz.reviewIndex + direction;
    if (newIndex >= 0 && newIndex < state.quiz.answers.length) {
        state.quiz.reviewIndex = newIndex;
        displayReviewQuestion();
    }
}

function displayReviewQuestion() {
    const index = state.quiz.reviewIndex;
    const answer = state.quiz.answers[index];
    const question = answer.question;

    // Update navigation
    document.getElementById('reviewCurrentQ').textContent = index + 1;
    document.getElementById('prevReviewQuestion').disabled = index === 0;
    document.getElementById('nextReviewQuestion').disabled = index === state.quiz.answers.length - 1;

    const body = document.getElementById('reviewModalBody');

    let statusClass = answer.userAnswer === null ? 'skipped' : (answer.correct ? 'correct' : 'incorrect');
    let statusIcon = answer.userAnswer === null ? '−' : (answer.correct ? '✓' : '✗');

    let content = `
        <div class="review-question">
            <div class="review-question-header">
                <span class="review-status ${statusClass}">${statusIcon}</span>
                <span class="review-question-title">Question ${index + 1}</span>
                <span class="review-question-type">${getQuestionTypeName(question.type)}</span>
            </div>
    `;

    if (question.type === 'log') {
        content += renderLogReview(answer, question.data);
    } else if (question.type === 'cvss') {
        content += renderCvssReview(answer, question.data);
    } else if (question.type === 'cve') {
        content += renderCveReview(answer, question.data);
    }

    content += '</div>';
    body.innerHTML = content;
}

function getQuestionTypeName(type) {
    const names = {
        log: 'Log Analysis',
        cvss: 'CVSS Scoring',
        cve: 'CVE Analysis'
    };
    return names[type] || type;
}

function renderLogReview(answer, scenario) {
    const userAnswerLabel = answer.userAnswer
        ? (eventTypes.find(e => e.id === answer.userAnswer)?.label || answer.userAnswer)
        : 'Skipped';
    const correctAnswerLabel = eventTypes.find(e => e.id === scenario.correctAnswer)?.label || scenario.correctAnswer;

    return `
        <div class="review-log-display">
            <pre>${scenario.log}</pre>
        </div>
        <div class="review-answers">
            <div class="review-answer-box your-answer ${!answer.correct && answer.userAnswer ? 'wrong' : ''}">
                <h5>Your Answer</h5>
                <p>${userAnswerLabel}</p>
            </div>
            <div class="review-answer-box correct-answer">
                <h5>Correct Answer</h5>
                <p>${correctAnswerLabel}</p>
            </div>
        </div>
        <div class="review-explanation">
            <h5>Explanation</h5>
            <p>${scenario.explanation}</p>
            <ul>
                ${scenario.indicators.map(ind => `<li>${ind}</li>`).join('')}
            </ul>
        </div>
    `;
}

function renderCvssReview(answer, scenario) {
    const userScore = answer.userAnswer !== null ? answer.userAnswer : 'Skipped';
    const userSeverity = answer.userAnswer !== null ? getSeverityFromScore(answer.userAnswer) : '';

    let metricsHtml = '';
    if (scenario.explanation) {
        for (const [metric, explanation] of Object.entries(scenario.explanation)) {
            const metricName = getMetricName(metric);
            const correctValue = scenario.correctMetrics[metric];
            metricsHtml += `<li><strong>${metricName} (${correctValue}):</strong> ${explanation}</li>`;
        }
    }

    return `
        <div class="review-vuln-description">
            ${scenario.description}
        </div>
        <div class="review-answers">
            <div class="review-answer-box your-answer ${!answer.correct && answer.userAnswer !== null ? 'wrong' : ''}">
                <h5>Your Score</h5>
                <p>${userScore}${userSeverity ? ` (${userSeverity})` : ''}</p>
            </div>
            <div class="review-answer-box correct-answer">
                <h5>Correct Score</h5>
                <p>${scenario.correctScore} (${scenario.severity})</p>
            </div>
        </div>
        <div class="review-explanation">
            <h5>Metric Breakdown</h5>
            <ul>
                ${metricsHtml}
            </ul>
        </div>
    `;
}

function renderCveReview(answer, cve) {
    const qType = answer.questionType || state.quiz.answers[state.quiz.reviewIndex].questionType || 'vulnType';

    let questionText, userAnswerLabel, correctAnswerLabel, explanation;

    // Try to get the question type from the answer object
    const questionType = answer.questionType || 'vulnType';

    if (questionType === 'vulnType') {
        questionText = 'What type of vulnerability is this?';
        userAnswerLabel = answer.userAnswer
            ? (vulnTypeOptions.find(o => o.id === answer.userAnswer)?.label || answer.userAnswer)
            : 'Skipped';
        correctAnswerLabel = vulnTypeOptions.find(o => o.id === cve.questions.vulnType.correct)?.label || cve.questions.vulnType.correct;
        explanation = cve.questions.vulnType.explanation;
    } else if (questionType === 'attackVector') {
        questionText = 'What is the primary attack vector?';
        userAnswerLabel = answer.userAnswer
            ? (attackVectorOptions.find(o => o.id === answer.userAnswer)?.label || answer.userAnswer)
            : 'Skipped';
        correctAnswerLabel = attackVectorOptions.find(o => o.id === cve.questions.attackVector.correct)?.label || cve.questions.attackVector.correct;
        explanation = cve.questions.attackVector.explanation;
    } else {
        questionText = 'What is the recommended mitigation?';
        userAnswerLabel = answer.userAnswer
            ? (mitigationOptions.find(o => o.id === answer.userAnswer)?.label || answer.userAnswer)
            : 'Skipped';
        correctAnswerLabel = mitigationOptions.find(o => o.id === cve.questions.mitigation.correct)?.label || cve.questions.mitigation.correct;
        explanation = cve.questions.mitigation.explanation;
    }

    return `
        <div class="review-cve-info">
            <h4>${cve.cveId} - ${cve.name}</h4>
            <p>${cve.description}</p>
        </div>
        <p style="color: var(--text-secondary); margin-bottom: 15px;"><strong>Question:</strong> ${questionText}</p>
        <div class="review-answers">
            <div class="review-answer-box your-answer ${!answer.correct && answer.userAnswer ? 'wrong' : ''}">
                <h5>Your Answer</h5>
                <p>${userAnswerLabel}</p>
            </div>
            <div class="review-answer-box correct-answer">
                <h5>Correct Answer</h5>
                <p>${correctAnswerLabel}</p>
            </div>
        </div>
        <div class="review-explanation">
            <h5>Explanation</h5>
            <p>${explanation}</p>
            <p style="margin-top: 15px;"><strong>Mitigation Details:</strong> ${cve.mitigationExplanation}</p>
        </div>
    `;
}

// Utility Functions
function shuffleArray(array) {
    const arr = [...array];
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

function getLogTypeName(type) {
    const names = {
        firewall: 'Firewall Log',
        ids: 'IDS/IPS Alert',
        webserver: 'Web Server Log',
        auth: 'Authentication Log',
        system: 'System Event Log'
    };
    return names[type] || type;
}
