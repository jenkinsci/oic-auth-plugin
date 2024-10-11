Behaviour.specify("#logoutFromIDP", 'oic-security-realm', 0, function(logoutFromIDP) {

    var endSessionConfig = document.querySelector('.endSessionConfig');

    if (endSessionConfig && logoutFromIDP) {
        endSessionConfig.style.display = logoutFromIDP.checked ? "block" : "none";

        logoutFromIDP.addEventListener("change", function() {
            endSessionConfig.style.display = logoutFromIDP.checked ? "block" : "none";
        });
    }
});
