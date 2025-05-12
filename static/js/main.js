// Main JavaScript for VulnScanner

document.addEventListener('DOMContentLoaded', function() {
    
    // Form validation
    const scanForm = document.querySelector('form[action*="scan"]');
    if (scanForm) {
        scanForm.addEventListener('submit', function(event) {
            const targetInput = document.getElementById('target');
            const legalCheck = document.getElementById('legal_check');
            
            // Basic URL validation
            if (targetInput && targetInput.value) {
                const url = targetInput.value.trim();
                
                // If it doesn't start with http:// or https://, check if it's at least a valid domain
                if (!url.startsWith('http://') && !url.startsWith('https://')) {
                    // Simple domain regex check
                    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
                    if (!domainRegex.test(url)) {
                        event.preventDefault();
                        alert('Please enter a valid URL (https://example.com) or domain name (example.com)');
                        return false;
                    }
                }
            }
            
            // Legal confirmation check
            if (legalCheck && !legalCheck.checked) {
                event.preventDefault();
                alert('You must confirm that you have permission to scan this target.');
                return false;
            }
        });
    }
    
    // Copy to clipboard functionality for report
    const copyButtons = document.querySelectorAll('.copy-btn');
    if (copyButtons.length > 0) {
        copyButtons.forEach(button => {
            button.addEventListener('click', function() {
                const textToCopy = this.getAttribute('data-copy');
                
                navigator.clipboard.writeText(textToCopy).then(() => {
                    // Change button text temporarily
                    const originalText = this.innerHTML;
                    this.innerHTML = '<i class="fas fa-check me-1"></i>Copied!';
                    
                    setTimeout(() => {
                        this.innerHTML = originalText;
                    }, 2000);
                }).catch(err => {
                    console.error('Could not copy text: ', err);
                });
            });
        });
    }
    
    // Toggle visibility of vulnerability details
    const toggleButtons = document.querySelectorAll('.toggle-details');
    if (toggleButtons.length > 0) {
        toggleButtons.forEach(button => {
            button.addEventListener('click', function() {
                const detailsId = this.getAttribute('data-target');
                const detailsElement = document.getElementById(detailsId);
                
                if (detailsElement) {
                    detailsElement.classList.toggle('d-none');
                    
                    // Update button text
                    if (detailsElement.classList.contains('d-none')) {
                        this.innerHTML = '<i class="fas fa-plus-circle me-1"></i>Show Details';
                    } else {
                        this.innerHTML = '<i class="fas fa-minus-circle me-1"></i>Hide Details';
                    }
                }
            });
        });
    }
    
    // Tooltips initialization (if using Bootstrap tooltips)
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});
