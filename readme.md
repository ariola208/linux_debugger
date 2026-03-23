Explication détaillée

Considérez un débogueur comme un microscope puissant et un panneau de contrôle pour un programme en cours d'exécution. Alors que printf (afficher du texte à l'écran) est la forme la plus basique de débogage, un débogueur vous offre un contrôle et une vision bien plus profonds, sans avoir à modifier et recompiler votre code.

Voici ce qu'un débogueur Linux permet de faire :
1. Contrôler l'exécution

Vous pouvez exécuter un programme sous le contrôle du débogueur, ce qui vous permet de :

    Démarrer le programme.

    Placer des points d'arrêt (breakpoints) : Mettre le programme en pause à une ligne de code ou une fonction spécifique. *« Arrête-toi quand tu arrives à la ligne 42. »*

    Exécuter pas à pas :

        Entrer dans (step into) : Entrer dans une fonction pour voir ce qu'elle fait.

        Passer (step over) : Exécuter une fonction en une seule étape sans entrer à l'intérieur.

        Continuer (continue) : Reprendre l'exécution jusqu'au prochain point d'arrêt.

    Détacher (detach) : Retirer le débogueur d'un processus en cours sans le tuer.

2. Inspecter l'état

Lorsque le programme est en pause (à un point d'arrêt), le débogueur vous permet d'examiner :

    Le code source : Il affiche la ligne de code qui va être exécutée.

    Les variables : Vous pouvez afficher la valeur de n'importe quelle variable (print ma_variable).

    La pile d'appels (call stack) : Vous pouvez voir la chaîne de fonctions qui a été appelée pour arriver à la ligne actuelle. « Comment suis-je arrivé ici ? »

    Les registres du processeur : Pour un débogage de très bas niveau (assembleur).

    La mémoire : Vous pouvez examiner des zones spécifiques de la mémoire (x/10xw 0x7fffffff).

3. Modifier l'état

Un débogueur n'est pas seulement un outil d'observation ; il permet aussi d'agir :

    Changer la valeur d'une variable à la volée pour tester un comportement différent sans recompiler.

    Appeler des fonctions manuellement depuis le débogueur.

    Ignorer des points d'arrêt après un certain nombre de passages (breakpoints conditionnels).

Exemples de débogueurs Linux
Nom	Description
GDB (GNU Debugger)	Le débogueur standard sur Linux. Il fonctionne en ligne de commande (terminal) et supporte de nombreux langages (C, C++, Rust, Go, etc.). C'est le plus puissant et le plus utilisé.
LLDB	Le débogueur de la suite LLVM (compilateur Clang). Il est conçu pour être plus modulaire et plus rapide que GDB, et est souvent préféré pour le C++ moderne et Rust.
Valgrind	Bien que techniquement un framework d'instrumentation, il est surtout utilisé comme outil de débogage mémoire avec son outil Memcheck. Il détecte les fuites mémoire et les accès illégaux à la mémoire (segfaults).
strace / ltrace	Des outils plus simples qui tracent respectivement les appels système (interactions avec le noyau Linux) et les appels de bibliothèques. Ils sont très utiles pour comprendre ce qu'un programme fait sans avoir son code source.
IDE intégrés	La plupart des environnements de développement (VS Code, CLion, Qt Creator, Eclipse) intègrent GDB ou LLDB derrière une interface graphique, vous permettant de cliquer pour placer des points d'arrêt et survoler les variables avec la souris.
Cas d'utilisation typique

    Votre programme plante (Segmentation fault / Erreur de segmentation).
    Vous lancez le programme avec GDB, celui-ci s'arrête au moment du crash, et vous pouvez utiliser la commande backtrace (ou bt) pour voir exactement quelle fonction a causé l'erreur.

    Une variable a une valeur étrange.
    Vous placez un point d'arrêt juste avant la ligne suspecte et vous exécutez print ma_variable pour vérifier sa valeur réelle.

    Vous comprenez un code complexe.
    Vous exécutez un programme existant pas à pas pour suivre le flux d'exécution et comprendre comment les différentes parties interagissent.

En résumé

Un débogueur Linux (principalement GDB) est l'outil indispensable pour tout développeur C/C++ sous Linux. Il permet de contrôler l'exécution, d'inspecter l'état interne et de modifier le comportement d'un programme en cours d'exécution, sans avoir à le recompiler.
