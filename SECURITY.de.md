# Offenlegung von Sicherheitslücken

Diese Datei beschreibt den Prozess zur Offenlegung von Sicherheitslücken für dieses Plugin-Repository (id `ssh-guard`); sie ist kein Sicherheitsdesign-Dokument.

## Geltungsbereich

Umfasst: die Implementierung von `SSH 加固插件` (id `ssh-guard`), die Fähigkeitsdeklaration in `info.json`, das `web/`-Frontend und die `make dist`-Artefakte.

Nicht umfasst: Kernel- und Probleme des Protokolls — melden Sie diese gemäß [kore SECURITY.md](https://github.com/kore-pl/kore/blob/main/SECURITY.md); bekannte Schwachstellen in externen Abhängigkeiten bitte ebenfalls an das Upstream-Projekt melden.

## Unterstützte Versionen

| Version | Status | Hinweis |
| --- | --- | --- |
| `0.4.0` (aktuellste) | ✅ Wird angenommen und behoben | Sicherheitskorrekturen erfolgen nur für die neueste Patch-Version |
| Ältere `0.x`-Versionen | ❌ Nicht unterstützt | Bitte zuerst auf die neueste Version aktualisieren |

In `0.x` ist der Support minimal: nur der neueste Patch einer Minor-Linie erhält Korrekturen; ältere Patches werden nicht zurückportiert.

## Angriffsfläche dieses Repositories

- **RPC-Methoden**: alle `ssh-guard.*`-Methoden (siehe `README.md`); fehlende Parametervalidierung kann zu Rechteausweitung oder Injektion führen.
- **capabilities**: `info.json.capabilities` ist die vollständige Autorisierungsfläche des Plugins; jede zusätzliche Deklaration ist ein weiterer Angriffsvektor.
- **Eigener Prozess und UDS**: das Plugin läuft als eigener Prozess; der Socket wird von der Host-Shell erstellt, `chown kore-<id>`, Modus `0600`; das Umgehen von Socket-Berechtigungen oder das Verbinden mit dem Socket eines anderen Plugins ist eine Schwachstelle.
- **Host-Schreibfläche**: Schreibzugriffe außerhalb der tatsächlich gewährten capabilities (Dateien / Prozesse / Netzwerk / Datenbank) sind Schwachstellen.
- **Frontend**: `web/` läuft in einem iframe mit separater Origin und kommuniziert über postMessage mit der Host-Shell; XSS, Nachrichtenfälschung und das Lesen von Daten anderer Plugins sind Sicherheitsgrenzprobleme.

## Meldung

1. **Bevorzugt ein GitHub Security Advisory**: Security-Seite dieses Repositories → "Report a vulnerability" (privater Kanal, kein öffentliches Issue).
2. **E-Mail als Alternative**: `pengtang1024@users.noreply.github.com`, Betreff `[kore security] ssh-guard`.
3. **Keine öffentlichen Issues und keine PoCs in Diskussionen oder PRs veröffentlichen.**
4. Bitte angeben: betroffene Version, Reproduktionsschritte oder PoC, Auswirkungsabschätzung, bereits öffentlich bekannt, und Credit-Wunsch.

## Fristen und Offenlegung

- Eingangsbestätigung und Ersteinschätzung innerhalb von **72 Stunden**; komplexe Fälle erhalten anschließend einen Plan.
- Koordinierte Offenlegung nach der Korrektur, mit einer Standardfrist von **90 Tagen**; bei aktiver Ausnutzung bitte vorher abstimmen.
- Sicherheitskorrekturen nach dem Release in `CHANGELOG.md` vermerken (ohne Ausnutzungsdetails) und bei Bedarf eine Sicherheitsmeldung veröffentlichen.

## Danksagung

Credit wird mit Zustimmung des Melders in den Release-Notes gegeben; auf Wunsch anonym.
