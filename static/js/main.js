// ===== ENHANCED PROFESSIONAL CYBERSECURITY CTF THEME WITH LOCAL MEDIA =====

// Audio and background configuration
let audioPlayer = null;
let isPlaying = false;
let audioInitialized = false;
let currentBackgroundType = 'image'; // 'image', 'video', 'gif'
let audioRecoveryAttempts = 0;
let maxRecoveryAttempts = 3;

// Local media paths configuration
const mediaConfig = {
    audio: {
        backgroundMusic: "/static/audio/background-music.mp3"
    },
    backgrounds: {
        images: [
            "/static/images/cyber-bg-2.jpeg",
            "/static/images/cyber-bg-2.jpeg",
            "/static/images/cyber-bg-3.jpeg"
        ],
        videos: [
            "/static/videos/backgrounds/cyber-bg-1.mp4",
            "/static/videos/backgrounds/cyber-bg-2.mp4"
        ],
        gifs: [
            "/static/images/backgrounds/cyber-bg-1.gif",
            "/static/images/backgrounds/cyber-bg-2.gif"
        ]
    }
};

// Initialize theme on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeCyberTheme();
    createEnhancedCyberParticles();
    initializeBackgroundSystem();
    initializeSimpleMusicPlayer();
    addProfessionalAnimations();
    setupKeyboardShortcuts();
    initializeTooltips();
    loadSavedSettings();
    handlePageVisibility();
    setupMusicRecovery();
});

// ===== CYBER THEME INITIALIZATION =====
function initializeCyberTheme() {
    console.log('🛡️ Initializing Enhanced Professional Cybersecurity Theme...');
    
    // Add fade-in animation to all cards
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
        card.style.animationDelay = (index * 0.1) + 's';
        card.classList.add('fade-in');
    });
    
    // Initialize challenge cards
    updateChallengeCards();
    
    // Auto-hide alerts
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            alert.classList.add('fade-out');
            setTimeout(() => {
                if (alert.parentNode) {
                    alert.remove();
                }
            }, 300);
        }, 5000);
    });
    
    // Add typing effect to certain elements
    addTypingEffects();
}

// ===== DYNAMIC BACKGROUND SYSTEM =====
function initializeBackgroundSystem() {
    // Create background container
    const backgroundContainer = document.createElement('div');
    backgroundContainer.className = 'background-container';
    backgroundContainer.innerHTML = `
        <div class="background-image"></div>
        <div class="background-video">
            <video autoplay muted loop>
                <source src="" type="video/mp4">
            </video>
        </div>
        <div class="background-gif"></div>
        <div class="background-overlay"></div>
    `;
    document.body.appendChild(backgroundContainer);
    
    // Set initial background type
    document.body.setAttribute('data-bg-type', currentBackgroundType);
    
    console.log('🖼️ Background system initialized');
}

function setBackground(mediaPath, type = 'image') {
    console.log(`🖼️ Setting ${type} background: ${mediaPath}`);
    
    currentBackgroundType = type;
    document.body.setAttribute('data-bg-type', type);
    
    switch(type) {
        case 'image':
            document.documentElement.style.setProperty('--background-image', `url('${mediaPath}')`);
            break;
            
        case 'video':
            const video = document.querySelector('.background-video video source');
            if (video) {
                video.src = mediaPath;
                video.parentElement.load();
            }
            break;
            
        case 'gif':
            const gifElement = document.querySelector('.background-gif');
            if (gifElement) {
                gifElement.style.backgroundImage = `url('${mediaPath}')`;
            }
            break;
    }
    
    // Save to localStorage
    localStorage.setItem('ctf-background-path', mediaPath);
    localStorage.setItem('ctf-background-type', type);
    
    showNotification(`🎨 Background changed to ${type}: ${mediaPath.split('/').pop()}`, 'success');
}

function setBackgroundOverlay(opacity) {
    document.documentElement.style.setProperty('--background-overlay', `rgba(10, 14, 26, ${opacity})`);
    localStorage.setItem('ctf-background-overlay', opacity);
    showNotification(`🎨 Background overlay set to ${Math.round(opacity * 100)}%`, 'info');
}

// ===== ENHANCED FLOATING CYBER PARTICLES =====
function createEnhancedCyberParticles() {
    const particlesContainer = document.createElement('div');
    particlesContainer.className = 'cyber-particles';
    document.body.appendChild(particlesContainer);
    
    // Create 80 particles of different types
    for (let i = 0; i < 80; i++) {
        createCyberParticle(particlesContainer);
    }
    
    // Continuously create new particles
    setInterval(() => {
        if (document.querySelectorAll('.cyber-particle').length < 100) {
            createCyberParticle(particlesContainer);
        }
    }, 2000);
}

function createCyberParticle(container) {
    const particle = document.createElement('div');
    particle.className = 'cyber-particle';
    
    // Randomly assign particle types (6 types available)
    const particleType = Math.floor(Math.random() * 6) + 1;
    particle.classList.add(`type-${particleType}`);
    
    // 30% chance for zigzag movement
    if (Math.random() < 0.3) {
        particle.classList.add('zigzag');
    }
    
    // Random position and timing
    particle.style.left = Math.random() * 100 + '%';
    particle.style.animationDelay = Math.random() * 10 + 's';
    
    // Random opacity variation
    particle.style.opacity = 0.3 + Math.random() * 0.4;
    
    container.appendChild(particle);
    
    // Remove particle after animation
    const removeTime = particleType <= 3 ? 12000 : 18000;
    setTimeout(() => {
        if (particle.parentNode) {
            particle.parentNode.removeChild(particle);
        }
    }, removeTime);
}

// ===== ENHANCED CONTINUOUS MUSIC SYSTEM =====
function initializeSimpleMusicPlayer() {
    // Prevent multiple initializations
    if (audioInitialized) {
        // Just check if music should be playing and continue
        const savedMusicState = localStorage.getItem('ctf-music-playing');
        if (savedMusicState === 'true' && audioPlayer) {
            ensureMusicContinues();
        }
        return;
    }
    
    // Create simple music toggle icon
    const musicToggle = document.createElement('div');
    musicToggle.className = 'music-toggle-icon';
    musicToggle.innerHTML = '<i class="fas fa-music"></i>';
    musicToggle.onclick = toggleBackgroundMusic;
    musicToggle.title = 'Toggle Background Music (Ctrl+M)';
    document.body.appendChild(musicToggle);
    
    // Create audio element with enhanced settings for continuous play
    audioPlayer = document.createElement('audio');
    audioPlayer.id = 'background-music';
    audioPlayer.loop = true;
    audioPlayer.volume = 0.3;
    audioPlayer.preload = 'auto';
    audioPlayer.crossOrigin = 'anonymous'; // Helps with CORS issues
    
    // Minimal event handling - only what's absolutely necessary
    audioPlayer.addEventListener('error', function(e) {
        console.log('🔇 Audio error:', e);
        // Try to recover after a brief delay
        setTimeout(() => {
            if (isPlaying && audioRecoveryAttempts < maxRecoveryAttempts) {
                audioRecoveryAttempts++;
                attemptMusicRecovery();
            }
        }, 2000);
    });
    
    // Track when audio successfully loads
    audioPlayer.addEventListener('loadeddata', function() {
        console.log('🎵 Audio loaded successfully');
        audioRecoveryAttempts = 0; // Reset recovery attempts on successful load
    });
    
    // Check if audio file exists and load it
    checkAndLoadAudio();
    
    document.body.appendChild(audioPlayer);
    audioInitialized = true;
    
    // Try to start music immediately if it was previously enabled
    setTimeout(() => {
        const savedMusicState = localStorage.getItem('ctf-music-playing');
        if (savedMusicState === 'true') {
            attemptAutoplay();
        }
    }, 1000);
    
    // Enhanced click handler for autoplay unlock
    let clickHandlerUsed = false;
    document.addEventListener('click', function handleAutoplayUnlock() {
        if (!clickHandlerUsed && audioPlayer && audioPlayer.src && audioPlayer.paused && isPlaying) {
            audioPlayer.play().then(() => {
                console.log('🎵 Audio unlocked and started');
                updateMusicUI(true);
                clickHandlerUsed = true;
            }).catch(e => console.log('Audio still blocked'));
        }
    });
}

function checkAndLoadAudio() {
    const audioUrl = mediaConfig.audio.backgroundMusic;
    
    fetch(audioUrl, { method: 'HEAD' })
        .then(response => {
            if (response.ok) {
                audioPlayer.src = audioUrl;
                console.log('🎵 Background music loaded successfully');
            } else {
                console.log('🔇 No background music file found at: ' + audioUrl);
            }
        })
        .catch(() => {
            console.log('🔇 Background music file not available');
        });
}

function attemptAutoplay() {
    if (audioPlayer && audioPlayer.src && audioPlayer.paused) {
        audioPlayer.play().then(() => {
            updateMusicUI(true);
            isPlaying = true;
            console.log('🎵 Music started and will play continuously');
        }).catch(e => {
            console.log('🔇 Autoplay prevented, waiting for user interaction');
            isPlaying = true;
            updateMusicUI(true);
        });
    }
}

function ensureMusicContinues() {
    if (isPlaying && audioPlayer && audioPlayer.paused) {
        audioPlayer.play().then(() => {
            console.log('🎵 Music resumed successfully');
            updateMusicUI(true);
        }).catch(e => {
            console.log('🔇 Could not resume music:', e);
            // Try again after a short delay
            setTimeout(() => {
                if (isPlaying && audioPlayer && audioPlayer.paused) {
                    audioPlayer.play().catch(e => console.log('Second resume attempt failed'));
                }
            }, 1000);
        });
    }
}

function attemptMusicRecovery() {
    console.log(`🔄 Attempting music recovery (attempt ${audioRecoveryAttempts}/${maxRecoveryAttempts})`);
    
    if (audioPlayer && audioPlayer.src && isPlaying) {
        // Try to reload and play the audio
        audioPlayer.load();
        setTimeout(() => {
            audioPlayer.play().then(() => {
                console.log('🎵 Music recovery successful');
                updateMusicUI(true);
            }).catch(e => {
                console.log('🔇 Music recovery failed:', e);
            });
        }, 500);
    }
}

function updateMusicUI(playing) {
    const musicIcon = document.querySelector('.music-toggle-icon');
    if (!musicIcon) return;
    
    const icon = musicIcon.querySelector('i');
    
    if (playing) {
        icon.className = 'fas fa-volume-up';
        musicIcon.classList.add('playing');
        musicIcon.classList.remove('muted');
    } else {
        icon.className = 'fas fa-volume-mute';
        musicIcon.classList.remove('playing');
        musicIcon.classList.add('muted');
    }
}

function toggleBackgroundMusic() {
    if (audioPlayer && audioPlayer.src) {
        if (audioPlayer.paused || !isPlaying) {
            audioPlayer.play().then(() => {
                updateMusicUI(true);
                isPlaying = true;
                localStorage.setItem('ctf-music-playing', 'true');
                showNotification('🎵 Background music enabled - will play continuously', 'info');
            }).catch(e => {
                showNotification('🔇 Audio autoplay prevented by browser', 'warning');
                console.log('Audio play failed:', e);
            });
        } else {
            audioPlayer.pause();
            updateMusicUI(false);
            isPlaying = false;
            localStorage.setItem('ctf-music-playing', 'false');
            showNotification('🔇 Background music disabled', 'info');
        }
    } else {
        showNotification('⚠️ No music track loaded. Add background-music.mp3 to /static/audio/', 'warning');
    }
}

// ===== ENHANCED PAGE VISIBILITY & FOCUS HANDLING =====
function handlePageVisibility() {
    // Handle page visibility changes (tab switching)
    document.addEventListener('visibilitychange', function() {
        if (!document.hidden && isPlaying && audioPlayer) {
            // Page became visible - ensure music continues
            setTimeout(() => {
                ensureMusicContinues();
            }, 100);
        }
    });
    
    // Handle window focus events
    window.addEventListener('focus', function() {
        if (isPlaying && audioPlayer) {
            setTimeout(() => {
                ensureMusicContinues();
            }, 100);
        }
    });
    
    // Handle page lifecycle events for modern browsers
    if ('onbeforeunload' in window) {
        window.addEventListener('beforeunload', function() {
            // Save current state before page unload
            if (audioPlayer && !audioPlayer.paused) {
                localStorage.setItem('ctf-music-playing', 'true');
                localStorage.setItem('ctf-music-time', audioPlayer.currentTime.toString());
            }
        });
    }
    
    // Handle page show event (back/forward navigation)
    window.addEventListener('pageshow', function(event) {
        if (event.persisted && isPlaying && audioPlayer) {
            // Page was loaded from cache
            setTimeout(() => {
                ensureMusicContinues();
            }, 200);
        }
    });
}

// ===== CONTINUOUS MUSIC RECOVERY SYSTEM =====
function setupMusicRecovery() {
    // Periodic check to ensure music continues playing
    setInterval(() => {
        if (isPlaying && audioPlayer && audioPlayer.paused && !document.hidden) {
            console.log('🔄 Detected music interruption, attempting recovery...');
            ensureMusicContinues();
        }
    }, 3000); // Check every 3 seconds
    
    // Additional recovery on user interaction
    ['click', 'keydown', 'touchstart'].forEach(eventType => {
        document.addEventListener(eventType, function() {
            if (isPlaying && audioPlayer && audioPlayer.paused) {
                ensureMusicContinues();
            }
        }, { passive: true, once: false });
    });
}

// ===== SETTINGS PERSISTENCE =====
function loadSavedSettings() {
    // Load saved background
    const savedBgPath = localStorage.getItem('ctf-background-path');
    const savedBgType = localStorage.getItem('ctf-background-type');
    const savedOverlay = localStorage.getItem('ctf-background-overlay');
    const savedMusicState = localStorage.getItem('ctf-music-playing');
    
    if (savedBgPath && savedBgType) {
        setBackground(savedBgPath, savedBgType);
    }
    
    if (savedOverlay) {
        setBackgroundOverlay(parseFloat(savedOverlay));
    }
    
    if (savedMusicState === 'true') {
        isPlaying = true;
        setTimeout(() => {
            updateMusicUI(true);
            // Try to restore previous playback position
            const savedTime = localStorage.getItem('ctf-music-time');
            if (savedTime && audioPlayer) {
                audioPlayer.currentTime = parseFloat(savedTime);
            }
        }, 200);
    }
}

function saveSettings() {
    const settings = {
        backgroundPath: localStorage.getItem('ctf-background-path'),
        backgroundType: localStorage.getItem('ctf-background-type'),
        backgroundOverlay: localStorage.getItem('ctf-background-overlay'),
        musicPlaying: localStorage.getItem('ctf-music-playing')
    };
    
    console.log('💾 Settings saved:', settings);
    return settings;
}

// ===== PROFESSIONAL ANIMATIONS =====
function addProfessionalAnimations() {
    // Enhanced hover effects for buttons
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(button => {
        button.addEventListener('mouseenter', function() {
            if (!this.disabled) {
                this.style.transform = 'translateY(-3px)';
                this.style.boxShadow = '0 8px 25px rgba(0, 212, 255, 0.3)';
            }
        });
        
        button.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
            this.style.boxShadow = '';
        });
    });
    
    // Enhanced click effects - NO AUDIO INTERACTION AT ALL
    document.addEventListener('click', function(e) {
        // Only create ripple effect, never touch audio
        if (e.target.classList.contains('btn') && !e.target.closest('.music-toggle-icon')) {
            createEnhancedClickRipple(e);
        }
    });
}

function createEnhancedClickRipple(e) {
    const button = e.target;
    const ripple = document.createElement('span');
    const rect = button.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const x = e.clientX - rect.left - size / 2;
    const y = e.clientY - rect.top - size / 2;
    
    ripple.style.cssText = `
        position: absolute;
        width: ${size}px;
        height: ${size}px;
        left: ${x}px;
        top: ${y}px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(0, 212, 255, 0.4) 0%, transparent 70%);
        pointer-events: none;
        animation: ripple 0.8s ease-out;
        z-index: 0;
    `;
    
    button.style.position = 'relative';
    button.style.overflow = 'hidden';
    button.appendChild(ripple);
    
    setTimeout(() => {
        if (ripple.parentNode) {
            ripple.parentNode.removeChild(ripple);
        }
    }, 800);
}

// ===== CHALLENGE CARD UPDATES =====
function updateChallengeCards() {
    const challengeCards = document.querySelectorAll('.challenge-card');
    challengeCards.forEach(card => {
        // Add category data attribute
        const categoryBadge = card.querySelector('.badge');
        if (categoryBadge) {
            const category = categoryBadge.textContent.trim();
            card.setAttribute('data-category', category);
        }
        
        // Add status classes
        const solvedIcon = card.querySelector('.fa-check-circle');
        const lockedIcon = card.querySelector('.fa-lock');
        
        if (solvedIcon) {
            card.classList.add('solved');
        } else if (lockedIcon) {
            card.classList.add('locked');
        } else {
            card.classList.add('unlocked');
        }
        
        // Add enhanced hover effect
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-8px) scale(1.02)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = '';
        });
    });
}

// ===== TYPING EFFECTS =====
function addTypingEffects() {
    const typingElements = document.querySelectorAll('.typing-effect');
    typingElements.forEach(element => {
        const text = element.textContent;
        element.textContent = '';
        element.style.width = '0';
        
        setTimeout(() => {
            element.style.width = text.length + 'ch';
            let i = 0;
            const typeInterval = setInterval(() => {
                element.textContent += text[i];
                i++;
                if (i >= text.length) {
                    clearInterval(typeInterval);
                }
            }, 50);
        }, 500);
    });
}

// ===== TOOLTIPS =====
function initializeTooltips() {
    try {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl, {
                customClass: 'cyber-tooltip'
            });
        });
    } catch(e) {
        console.log('Bootstrap tooltips not available');
    }
}

// ===== ENHANCED MODALS =====
function openChallengeModal(id, title, description) {
    document.getElementById('challengeId').value = id;
    document.getElementById('challengeTitle').textContent = title;
    document.getElementById('challengeDescription').innerHTML = description;
    document.getElementById('challengeResult').innerHTML = '';
    document.getElementById('challengeInput').value = '';
    
    // Add modal animation
    const modal = document.getElementById('challengeModal');
    modal.classList.add('fade-in');
    
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
    
    // Focus on input after modal is shown
    modal.addEventListener('shown.bs.modal', function () {
        document.getElementById('challengeInput').focus();
    });
}

// ===== ENHANCED FLAG SUBMISSION =====
if (document.getElementById('challengeForm')) {
    document.getElementById('challengeForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const submitBtn = this.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;
        
        // Add loading animation
        submitBtn.innerHTML = '<div class="loading-spinner"></div> Processing...';
        submitBtn.disabled = true;
        
        const formData = new FormData();
        formData.append('challenge_id', document.getElementById('challengeId').value);
        formData.append('flag', document.getElementById('challengeInput').value);
        
        fetch('/submit_flag', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            const resultDiv = document.getElementById('challengeResult');
            if (data.success) {
                resultDiv.innerHTML = `
                    <div class="alert alert-success fade-in">
                        <i class="fas fa-check-circle"></i> ${data.message}
                        <div class="mt-2">
                            <span class="badge badge-success">SUCCESS</span>
                        </div>
                    </div>
                `;
                
                // Create enhanced success effect
                createEnhancedSuccessEffect();
                
                setTimeout(() => location.reload(), 2000);
            } else {
                resultDiv.innerHTML = `
                    <div class="alert alert-danger fade-in">
                        <i class="fas fa-times-circle"></i> ${data.message}
                        <div class="mt-2">
                            <span class="badge badge-danger">INCORRECT</span>
                        </div>
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('challengeResult').innerHTML = 
                '<div class="alert alert-danger">Network error occurred. Please try again.</div>';
        })
        .finally(() => {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        });
    });
}

// ===== ENHANCED SUCCESS EFFECT =====
function createEnhancedSuccessEffect() {
    // Create multiple particle bursts
    const colors = ['var(--cyber-green)', 'var(--cyber-blue)', 'var(--cyber-purple)'];
    
    for (let burst = 0; burst < 3; burst++) {
        setTimeout(() => {
            for (let i = 0; i < 15; i++) {
                setTimeout(() => {
                    const particle = document.createElement('div');
                    particle.style.cssText = `
                        position: fixed;
                        top: 50%;
                        left: 50%;
                        width: ${4 + Math.random() * 6}px;
                        height: ${4 + Math.random() * 6}px;
                        background: ${colors[Math.floor(Math.random() * colors.length)]};
                        border-radius: 50%;
                        pointer-events: none;
                        z-index: 9999;
                        box-shadow: 0 0 15px currentColor;
                    `;
                    
                    const angle = (i / 15) * Math.PI * 2;
                    const distance = 80 + Math.random() * 80;
                    const duration = 1200 + Math.random() * 800;
                    
                    document.body.appendChild(particle);
                    
                    particle.animate([
                        {
                            transform: 'translate(-50%, -50%) scale(0) rotate(0deg)',
                            opacity: 1
                        },
                        {
                            transform: `translate(${Math.cos(angle) * distance - 50}%, ${Math.sin(angle) * distance - 50}%) scale(1.5) rotate(360deg)`,
                            opacity: 0
                        }
                    ], {
                        duration: duration,
                        easing: 'ease-out'
                    }).onfinish = () => particle.remove();
                }, i * 30);
            }
        }, burst * 200);
    }
}

// ===== NOTIFICATIONS =====
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} position-fixed fade-in`;
    notification.style.cssText = `
        top: 20px;
        right: 20px;
        z-index: 9999;
        min-width: 300px;
        max-width: 400px;
        backdrop-filter: blur(20px);
    `;
    notification.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="fas fa-info-circle me-2"></i>
            ${message}
            <button type="button" class="btn-close ms-auto" onclick="this.parentElement.parentElement.remove()"></button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (notification.parentNode) {
            notification.classList.add('fade-out');
            setTimeout(() => notification.remove(), 300);
        }
    }, 4000);
}

// ===== KEYBOARD SHORTCUTS =====
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl+M to toggle music
        if ((e.ctrlKey || e.metaKey) && e.key === 'm') {
            e.preventDefault();
            toggleBackgroundMusic();
        }
        
        // Ctrl+B to cycle backgrounds
        if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
            e.preventDefault();
            cycleBackground();
        }
        
        // Ctrl+/ for search
        if ((e.ctrlKey || e.metaKey) && e.key === '/') {
            e.preventDefault();
            const searchInput = document.querySelector('input[type="search"], input[placeholder*="search"]');
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        }
        
        // Escape to close modals
        if (e.key === 'Escape') {
            const openModals = document.querySelectorAll('.modal.show');
            openModals.forEach(modal => {
                const bsModal = bootstrap.Modal.getInstance(modal);
                if (bsModal) bsModal.hide();
            });
        }
    });
}

// ===== UTILITY FUNCTIONS =====
function cycleBackground() {
    const currentType = currentBackgroundType;
    const availableBackgrounds = mediaConfig.backgrounds[currentType + 's'];
    
    if (availableBackgrounds && availableBackgrounds.length > 0) {
        const currentPath = localStorage.getItem('ctf-background-path');
        const currentIndex = availableBackgrounds.indexOf(currentPath);
        const nextIndex = (currentIndex + 1) % availableBackgrounds.length;
        
        setBackground(availableBackgrounds[nextIndex], currentType);
    }
}

// ===== SCOREBOARD ENHANCEMENTS =====
if (window.location.pathname === '/scoreboard') {
    setInterval(function() {
        if (!document.hidden) {
            const table = document.querySelector('.table');
            if (table) {
                table.style.opacity = '0.7';
                setTimeout(() => location.reload(), 500);
            }
        }
    }, 30000);
}

// Add CSS for enhanced animations
const enhancedStyle = document.createElement('style');
enhancedStyle.textContent = `
    .fade-out {
        opacity: 0;
        transform: translateY(-10px);
        transition: all 0.3s ease;
    }
    
    @keyframes ripple {
        to {
            transform: scale(3);
            opacity: 0;
        }
    }
    
    .cyber-tooltip {
        background: var(--gradient-surface) !important;
        border: 1px solid var(--border-accent) !important;
        color: var(--text-primary) !important;
    }
`;
document.head.appendChild(enhancedStyle);

// ===== INITIALIZATION COMPLETE =====
console.log('🛡️ Enhanced Professional Cybersecurity CTF Theme Loaded Successfully');
console.log('🎵 Music System: Enhanced continuous playback enabled');
console.log('🖼️ Background System: Image/Video/GIF support enabled');
console.log('💫 Particles: Enhanced system with 80+ particles');
console.log('⌨️ Keyboard Shortcuts:');
console.log('  • Ctrl+M: Toggle background music');
console.log('  • Ctrl+B: Cycle backgrounds');
console.log('  • Ctrl+/: Focus search');
console.log('  • Escape: Close modals');

// Make functions globally available
window.openChallengeModal = openChallengeModal;
window.showNotification = showNotification;
window.toggleBackgroundMusic = toggleBackgroundMusic;
window.setBackground = setBackground;
window.setBackgroundOverlay = setBackgroundOverlay;
window.createEnhancedSuccessEffect = createEnhancedSuccessEffect;
window.saveSettings = saveSettings;
window.cycleBackground = cycleBackground;
window.ensureMusicContinues = ensureMusicContinues;