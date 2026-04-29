# Browar Panel

Panel do browaru z logowaniem, lista zadan, magazynem, produktami i rezerwacjami.

## Start lokalny

```powershell
node server.js
```

Nastepnie wejdz na `http://localhost:3000/`.

Konto startowe:

- login: `admin`
- haslo: `admin123`

## Wdrozenie

Najprostsza opcja to Render. Projekt ma juz `render.yaml`.

## Wybudzanie Render

Jesli chcesz wybudzac darmowy serwer przez `cron-job.org`, uzyj:

- `GET https://twoj-adres.onrender.com/wake`
- harmonogram: co `13` minut
- cron: `*/13 * * * *`

Moze tez dzialac adres:

- `GET https://twoj-adres.onrender.com/api/wake`

Polecany jest krotszy `/wake`.
