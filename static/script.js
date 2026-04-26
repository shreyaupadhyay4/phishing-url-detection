document.addEventListener("DOMContentLoaded", () => {
    const cards = document.querySelectorAll(".neon-card");

    cards.forEach((card) => {
        card.addEventListener("mousemove", (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            card.style.background = `
                radial-gradient(circle at ${x}px ${y}px, rgba(159, 239, 0, 0.10), transparent 24%),
                rgba(16, 24, 39, 0.88)
            `;
        });

        card.addEventListener("mouseleave", () => {
            card.style.background = "rgba(16, 24, 39, 0.88)";
        });
    });

    const supportForm = document.querySelector("[data-support-form]");
    if (supportForm) {
        supportForm.addEventListener("submit", () => {
            window.setTimeout(() => {
                alert("Support ticket submitted. Our technical team will review it shortly.");
            }, 50);
        });
    }

    document.querySelectorAll("[data-google-auth]").forEach((button) => {
        button.addEventListener("click", () => {
            alert("Google authentication is not configured yet. Please use username and password login.");
        });
    });
});
