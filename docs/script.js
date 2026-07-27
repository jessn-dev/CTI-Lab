// Language switcher for the code-snippets panel (cURL / Python / JavaScript)
function switchLang(lang, event) {
    document.querySelectorAll('.lang').forEach(el => el.classList.add('hidden'));
    const target = document.querySelector('.lang-' + lang);
    if (target) target.classList.remove('hidden');
    document.querySelectorAll('.code-header .tab').forEach(el => {
        el.classList.remove('active');
        el.setAttribute('aria-selected', 'false');
    });
    event.currentTarget.classList.add('active');
    event.currentTarget.setAttribute('aria-selected', 'true');
}

document.addEventListener('DOMContentLoaded', () => {
    // Scroll-spy: highlight the sidebar link for the section in view
    const sections = document.querySelectorAll('main section');
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                document.querySelectorAll('.nav-links li').forEach(li => li.classList.remove('active'));
                const link = document.querySelector(`.nav-links a[href="#${entry.target.id}"]`);
                if (link) link.parentElement.classList.add('active');
            }
        });
    }, { rootMargin: '-10% 0px -70% 0px', threshold: 0 });
    sections.forEach(s => observer.observe(s));

    // Copy-to-clipboard on each code block
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const code = btn.parentElement.querySelector('code');
            const text = (code ? code.innerText : '').trim();
            try {
                await navigator.clipboard.writeText(text);
                btn.textContent = 'Copied';
                btn.classList.add('copied');
                setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1600);
            } catch (e) {
                btn.textContent = 'Ctrl+C';
                setTimeout(() => { btn.textContent = 'Copy'; }, 1600);
            }
        });
    });
});
