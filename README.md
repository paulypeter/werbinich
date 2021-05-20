![GitHub](https://img.shields.io/github/license/paulypeter/werbinich) ![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/paulypeter/werbinich) ![GitHub issues](https://img.shields.io/github/issues-raw/paulypeter/werbinich) ![GitHub last commit](https://img.shields.io/github/last-commit/paulypeter/werbinich) [![https://werbinich.xyz](https://img.shields.io/badge/online-werbinich.xyz-blue)](https://werbinich.xyz)

# werbinich

complementing https://paulypeter.github.io/werbinichbot/

[Zur Seite](https://werbinich.peter-pauly.eu)

## Was ist das?

Die Seite soll dabei helfen, ohne Klebezettel "Wer bin ich?" zu spielen.

## Wie funktioniert das?

Die Seite funktioniert zusammen mit dem WerBinIchHelferBot. Spieler:innen ohne Telegram können so mitspielen!

Es ist eine Registrierung notwendig.
Dabei werden ein Nutzername und ein von anderen Spieler:innen einsehbarer Name angegeben.
Außerdem muss ein Passwort vergeben werden.
Danach kann einem bestehenden Spiel unter Kenntnis des Passworts beigetreten oder ein neues Spiel erstellt werden.

## Welche Daten werden gespeichert?

Ähnlich zum Bot werden hier gespeichert:
- der Nutzername
- der angegebene Name
- ein Hash des angegebenen Passworts

Beim Verlassen eines Spiels werden für Spieler:innen die Spiel-ID sowie der vergebene Charakter gelöscht.

Die Daten können auf Anfrage gelöscht werden. Irgendwann wird dafür auch eine Funktion zur Verfügung gestellt.

## Requirements

For pip requirements, see `requirements.txt`.

Furthermore, a running `Redis` instance is needed.

__IMPORTANT__

Before running the server in prod, set `use_debugger=False` in `werbinich.py`.
