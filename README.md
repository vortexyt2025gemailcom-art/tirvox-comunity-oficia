# Tirvox APK · servidor

Recibe y reparte archivos APK (cuentas, likes, comentarios, fotos y video). Un solo archivo: `server.js`, sin dependencias, Node 18+.

## Pasos
1. Crea un repositorio en GitHub y sube `server.js`, `package.json` y `README.md`.
2. GitHub solo guarda el código: lo ejecuta un host conectado al repo (Render, Railway, Koyeb, Fly.io). Ejemplo en Render: New > Web Service > elige este repo > Start Command: `node server.js`.
3. Variables de entorno en el host:
   - `OWNER_HASH` = huella del código del dueño (archivo `OWNER_HASH.txt`; **no la subas a GitHub**).
   - `DATA_DIR` = carpeta de un disco persistente (ej. `/data`). Sin disco persistente, cuentas y APK se borran cuando el servidor reinicia.
4. Copia la URL del servidor (ej. `https://tirvox.onrender.com`) y pégala en `index-servidor.html`, donde dice `PEGA-AQUI-LA-URL-DE-TU-SERVIDOR`. Sube ese HTML a Netlify.
5. Dueño: toca 5 veces la esquina superior izquierda de la página e ingresa tu código.
