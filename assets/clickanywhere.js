document.addEventListener("DOMContentLoaded", function() {
    // Sélectionne tous les éléments qui correspondent à la classe
    var cardHeaders = document.querySelectorAll('.card-header.d-flex.justify-content-between.hide-border-bottom');

    // Boucle à travers chaque élément et ajoute un écouteur d'événement de clic
    cardHeaders.forEach(function(cardHeader) {
        cardHeader.addEventListener('click', function() {
            // Redirige l'utilisateur vers l'URL du lien contenu dans le bloc cliquable
            var link = cardHeader.querySelector('a');
            if (link) {
                window.location.href = link.href;
            }
        });
    });
