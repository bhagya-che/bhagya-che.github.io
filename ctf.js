// CTF Challenge Data
const CTF_CHALLENGES = {
    auth: {
        id: 'auth',
        name: 'Authentication Bypass',
        difficulty: 'easy',
        flag: 'FLAG{DEBUG_MODE_ENABLED}',
        solved: false,
        hint: "Check the page source (Ctrl+U) and try adding ?debug=true to the URL"
    }
};

// Initialize CTF
document.addEventListener('DOMContentLoaded', function() {
    initializeCTF();
    setupEventListeners();
    console.log('🔒 CTF Training Ground Loaded');
    console.log('💡 Hint: Check the page source for flags and vulnerabilities!');
});

function initializeCTF() {
    // Check if challenge is already solved (from localStorage)
    const solvedChallenges = JSON.parse(localStorage.getItem('solvedCTFs') || '[]');
    if (solvedChallenges.includes('auth')) {
        markChallengeAsSolved('auth');
    }
    
    // Add hidden flag to page source
    addHiddenFlag();
}

function setupEventListeners() {
    // Login form submission
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLoginAttempt);
    }

    // Smooth scroll for navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            } else if (this.getAttribute('href') === 'index.html') {
                window.location.href = 'index.html';
            }
        });
    });
}

function handleLoginAttempt(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    // Check for debug parameter in URL
    const urlParams = new URLSearchParams(window.location.search);
    const debugMode = urlParams.get('debug');
    
    // Remove any existing error messages
    const existingError = document.querySelector('.error-message');
    if (existingError) {
        existingError.remove();
    }
    
    // Check for correct credentials OR debug mode
    if ((username === 'admin' && password === 'secretpass123') || debugMode === 'true') {
        showVictory('auth');
    } else {
        showError('Authentication failed. Hint: Check the page source (Ctrl+U) and try a debug parameter in the URL.');
    }
}

function showError(message) {
    const errorMsg = document.createElement('div');
    errorMsg.className = 'error-message';
    errorMsg.textContent = message;
    
    document.querySelector('.login-form').appendChild(errorMsg);
    
    // Remove error after 5 seconds
    setTimeout(() => {
        if (errorMsg.parentNode) {
            errorMsg.remove();
        }
    }, 5000);
}

function showVictory(challengeId) {
    const modal = document.getElementById('victoryModal');
    if (modal) {
        modal.style.display = 'flex';
        createConfetti();
        markChallengeAsSolved(challengeId);
        
        // Save to localStorage
        const solvedChallenges = JSON.parse(localStorage.getItem('solvedCTFs') || '[]');
        if (!solvedChallenges.includes(challengeId)) {
            solvedChallenges.push(challengeId);
            localStorage.setItem('solvedCTFs', JSON.stringify(solvedChallenges));
        }
    }
}

function closeVictory() {
    const modal = document.getElementById('victoryModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function markChallengeAsSolved(challengeId) {
    const statusElement = document.getElementById('authStatus');
    const challengeSection = document.getElementById('auth');
    
    if (statusElement) {
        statusElement.textContent = '✅ Solved';
        statusElement.style.color = 'var(--terminal-green)';
    }
    
    if (challengeSection) {
        challengeSection.classList.add('solved');
        // Unlock next challenge (placeholder)
        // unlockNextChallenge('injection');
    }
}

function addHiddenFlag() {
    // Add hidden comment to HTML source
    const flag = '<!-- DEBUG: flag=DEBUG_MODE_ENABLED -->';
    
    // Add console hints
    console.log('🔍 CTF Hint: Check the page source for hidden comments!');
    console.log('💡 Try adding ?debug=true to the URL');
    console.log('🎯 Valid credentials: admin / secretpass123');
}

function createConfetti() {
    const colors = ['#4ade80', '#60a5fa', '#fbbf24', '#f472b6', '#a371f7'];
    const confettiCount = 100;
    
    for (let i = 0; i < confettiCount; i++) {
        const confetti = document.createElement('div');
        confetti.style.cssText = `
            position: fixed;
            width: ${Math.random() * 8 + 4}px;
            height: ${Math.random() * 8 + 4}px;
            background: ${colors[Math.floor(Math.random() * colors.length)]};
            top: -10px;
            left: ${Math.random() * 100}%;
            z-index: 9999;
            animation: fall ${Math.random() * 3 + 2}s linear forwards;
            border-radius: 50%;
        `;
        
        document.body.appendChild(confetti);
        
        setTimeout(() => {
            confetti.remove();
        }, 5000);
    }
}

// Add confetti CSS
const style = document.createElement('style');
style.textContent = `
    @keyframes fall {
        to {
            transform: translateY(100vh) rotate(${Math.random() * 720}deg);
        }
    }
`;
document.head.appendChild(style);

// Binary background animation
function generateBinaryPattern() {
    const binaryBg = document.getElementById('binaryBg');
    if (!binaryBg) return;
    
    const columns = Math.floor(window.innerWidth / 20);
    const rows = Math.floor(window.innerHeight / 20);
    
    let binaryText = '';
    for (let i = 0; i < rows; i++) {
        for (let j = 0; j < columns; j++) {
            binaryText += Math.random() > 0.5 ? '1' : '0';
        }
        binaryText += '\n';
    }
    
    binaryBg.textContent = binaryText;
}

generateBinaryPattern();
window.addEventListener('resize', generateBinaryPattern);

// Parallax effect
window.addEventListener('scroll', () => {
    const scrollY = window.scrollY;
    const binaryBg = document.getElementById('binaryBg');
    const securityIcon = document.querySelector('.security-icon');
    
    if (binaryBg) {
        binaryBg.style.transform = `translateY(${-scrollY * 0.3}px)`;
    }
    
    if (securityIcon) {
        securityIcon.style.transform = `translate(${scrollY * 0.2}px, ${-scrollY * 0.1}px) rotate(${scrollY * 0.1}deg)`;
    }
});

console.log('🔓 CTF Training Ground initialized');
console.log('📊 Progress:', JSON.parse(localStorage.getItem('solvedCTFs') || '[]').length, 'challenges solved');