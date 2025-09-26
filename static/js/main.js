// Atualizar data e hora em tempo real
function updateDateTime() {
    const now = new Date();
    
    // Formatar data
    const dateOptions = { 
        weekday: 'long', 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric' 
    };
    const currentDate = now.toLocaleDateString('pt-BR', dateOptions);
    document.getElementById('current-date').textContent = currentDate;
    
    // Formatar hora
    const timeOptions = { 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit' 
    };
    const currentTime = now.toLocaleTimeString('pt-BR', timeOptions);
    document.getElementById('current-time').textContent = currentTime;
}

// Efeito de digitação no título
function typeWriterEffect() {
    const title = document.querySelector('.welcome-header h1');
    if (!title) return;
    
    const text = title.textContent;
    title.textContent = '';
    title.style.visibility = 'visible';
    
    let i = 0;
    const typeWriter = setInterval(() => {
        if (i < text.length) {
            title.textContent += text.charAt(i);
            i++;
        } else {
            clearInterval(typeWriter);
        }
    }, 80);
}

// Inicializar quando o DOM estiver carregado
document.addEventListener('DOMContentLoaded', function() {
    updateDateTime();
    typeWriterEffect();
    
    // Atualizar data e hora a cada segundo
    setInterval(updateDateTime, 1000);
    
    // Adicionar efeitos de hover dinâmicos
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-10px)';
        });
        
        card.addEventListener('mouseleave', function() {
            if (!this.classList.contains('disabled')) {
                this.style.transform = 'translateY(0)';
            }
        });
    });
});