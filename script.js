document.addEventListener('DOMContentLoaded', function() {
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
    const navLinks = document.querySelector('.nav-links');
    
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', function() {
            navLinks.classList.toggle('active');
        });
    }

    const header = document.querySelector('.header');
    let lastScroll = 0;
    
    window.addEventListener('scroll', function() {
        const currentScroll = window.pageYOffset;
        
        if (currentScroll > 100) {
            header.style.boxShadow = '0 2px 20px rgba(0, 0, 0, 0.1)';
        } else {
            header.style.boxShadow = 'none';
        }
        
        lastScroll = currentScroll;
    });

    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);
    
    document.querySelectorAll('.feature-card, .invest-card, .asset-card').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });

    // Automatically show chat button after 10 seconds
    const chatButton = document.getElementById('chat-prompt-trigger');
    const chatModal = document.getElementById('chat-modal');
    const closeBtnX = document.getElementById('modal-close-x');
    const closeBtnDropdown = document.getElementById('modal-close-dropdown');

    if (chatButton) {
        setTimeout(() => {
            chatButton.classList.add('visible');
        }, 10000);

        chatButton.addEventListener('click', () => {
            chatButton.style.display = 'none';
            chatModal.classList.add('active');
        });
    }

    function closeChat() {
        chatModal.classList.remove('active');
        chatButton.style.display = 'block';
        chatButton.classList.add('visible');
    }

    if (closeBtnX) closeBtnX.addEventListener('click', closeChat);
    if (closeBtnDropdown) closeBtnDropdown.addEventListener('click', closeChat);
});