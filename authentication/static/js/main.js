document.addEventListener('DOMContentLoaded', function() {
    /**
     * Fonction pour activer/désactiver la visibilité du mot de passe
     */
    function setupPasswordToggles() {
        const toggleButtons = document.querySelectorAll('.toggle-password');
        
        toggleButtons.forEach(button => {
            button.addEventListener('click', function() {
                const targetId = this.getAttribute('data-target');
                const passwordInput = document.getElementById(targetId);
                
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    this.innerHTML = '<i class="icon-eye-off"></i>';
                } else {
                    passwordInput.type = 'password';
                    this.innerHTML = '<i class="icon-eye"></i>';
                }
            });
        });
    }

    /**
     * Fonction pour vérifier la force du mot de passe
     */
    function setupPasswordStrengthChecker() {
        const passwordInput = document.getElementById('password');
        
        if (!passwordInput) return;
        
        const requirements = {
            length: document.getElementById('length'),
            uppercase: document.getElementById('uppercase'),
            lowercase: document.getElementById('lowercase'),
            number: document.getElementById('number'),
            special: document.getElementById('special')
        };
        
        function checkPasswordStrength(password) {
            const checks = {
                length: password.length >= 8,
                uppercase: /[A-Z]/.test(password),
                lowercase: /[a-z]/.test(password),
                number: /[0-9]/.test(password),
                special: /[^A-Za-z0-9]/.test(password)
            };
            
            for (const [key, element] of Object.entries(requirements)) {
                if (!element) continue;
                
                if (checks[key]) {
                    element.classList.add('valid');
                } else {
                    element.classList.remove('valid');
                }
            }
        }
        
        passwordInput.addEventListener('input', function() {
            checkPasswordStrength(this.value);
        });
    }

    /**
     * Fonction pour faire disparaître les messages d'alerte après un délai
     */
    function setupMessageDismissal() {
        const messages = document.querySelectorAll('.message:not(.error)');
        
        messages.forEach(message => {
            setTimeout(() => {
                message.style.opacity = '0';
                setTimeout(() => {
                    message.style.display = 'none';
                }, 300);
            }, 5000);
        });
    }

    /**
     * Fonction pour formatter l'entrée OTP
     */
    function setupOTPInput() {
        const otpInput = document.querySelector('.otp-input');
        
        if (!otpInput) return;
        
        otpInput.addEventListener('input', function() {
            // Ne garder que les chiffres
            this.value = this.value.replace(/[^0-9]/g, '');
            
            // Limiter à 6 chiffres
            if (this.value.length > 6) {
                this.value = this.value.slice(0, 6);
            }
        });
    }

    /**
     * Gestionnaire pour la validation des formulaires
     */
    function setupFormValidation() {
        const forms = document.querySelectorAll('form');
        
        forms.forEach(form => {
            form.addEventListener('submit', function(event) {
                const requiredFields = form.querySelectorAll('[required]');
                let valid = true;
                
                requiredFields.forEach(field => {
                    if (!field.value.trim()) {
                        valid = false;
                        field.classList.add('invalid');
                        
                        // Ajouter un message d'erreur s'il n'existe pas déjà
                        let errorElement = field.parentNode.querySelector('.error-text');
                        if (!errorElement) {
                            errorElement = document.createElement('div');
                            errorElement.className = 'error-text';
                            errorElement.textContent = 'Ce champ est requis.';
                            field.parentNode.appendChild(errorElement);
                        }
                    } else {
                        field.classList.remove('invalid');
                        const errorElement = field.parentNode.querySelector('.error-text');
                        if (errorElement) {
                            errorElement.remove();
                        }
                    }
                });
                
                if (!valid) {
                    event.preventDefault();
                }
            });
        });
    }

    /**
     * Initialisation de toutes les fonctionnalités JavaScript
     */
    function initializeApp() {
        setupPasswordToggles();
        setupPasswordStrengthChecker();
        setupMessageDismissal();
        setupOTPInput();
        setupFormValidation();
    }

    // Démarrer l'application
    initializeApp();
});