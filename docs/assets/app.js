/* Documentation Generator JavaScript Features */

/* Back-to-Top Button */
(function() {
    // Inject CSS for the back-to-top button
    const css = `
        #back-to-top {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background-color: var(--primary-color, #667eea);
            color: white;
            border: none;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            font-size: 24px;
            cursor: pointer;
            opacity: 0.7;
            transition: opacity 0.3s, transform 0.3s;
            z-index: 1000;
            display: none;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        #back-to-top:hover {
            opacity: 1;
            transform: scale(1.1);
        }
    `;
    const style = document.createElement('style');
    style.textContent = css;
    document.head.appendChild(style);
})();

document.addEventListener('DOMContentLoaded', function() {
    // Create button element
    const backToTopButton = document.createElement('button');
    backToTopButton.id = 'back-to-top';
    backToTopButton.innerHTML = '▲';
    backToTopButton.title = 'Back to Top';
    document.body.appendChild(backToTopButton);

    // Show button when user scrolls down 300px
    const toggleBackToTopButton = function() {
        if (window.pageYOffset > 300) {
            backToTopButton.style.display = 'flex';
        } else {
            backToTopButton.style.display = 'none';
        }
    };

    // Scroll to top when button is clicked
    backToTopButton.addEventListener('click', function(e) {
        e.preventDefault();
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });

    // Listen for scroll events
    window.addEventListener('scroll', toggleBackToTopButton);
    toggleBackToTopButton(); // Initial check
});

/* Smooth scrolling for anchor links */
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth'
            });
        }
    });
});

/* Syntax highlighting enhancement (basic) */
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('pre code').forEach((block) => {
        block.parentElement.style.position = 'relative';
        
        // Add copy button
        const copyButton = document.createElement('button');
        copyButton.textContent = 'Copy';
        copyButton.style.position = 'absolute';
        copyButton.style.top = '8px';
        copyButton.style.right = '8px';
        copyButton.style.padding = '4px 8px';
        copyButton.style.background = 'rgba(0,0,0,0.7)';
        copyButton.style.color = 'white';
        copyButton.style.border = 'none';
        copyButton.style.borderRadius = '4px';
        copyButton.style.fontSize = '12px';
        copyButton.style.cursor = 'pointer';
        copyButton.style.zIndex = '10';
        
        copyButton.addEventListener('click', function() {
            const code = block.textContent;
            navigator.clipboard.writeText(code).then(() => {
                const originalText = copyButton.textContent;
                copyButton.textContent = 'Copied!';
                setTimeout(() => {
                    copyButton.textContent = originalText;
                }, 2000);
            });
        });
        
        block.parentElement.appendChild(copyButton);
    });
});

console.log('Documentation generator JavaScript loaded.');