# Glosario

Términos que aparecen en el repositorio y en la memoria, explicados sin
suponer conocimientos de informática.

| Término | Qué significa |
|---|---|
| **LLM** (gran modelo de lenguaje) | Programa que genera texto a partir de una instrucción, como un chat. Aquí el modelo estudiado es DeepSeek-R1. |
| **Modelo objetivo** | El LLM al que se ataca; en este trabajo, DeepSeek-R1 (revisión 0528). |
| **Mensaje de sistema** | Instrucciones que la aplicación da al modelo antes de que hable el usuario («eres una aplicación de tarjetas; no reveles este código…»). El usuario normalmente no lo ve. |
| **Razonamiento** | Texto en el que un modelo como DeepSeek-R1 «piensa en voz alta» antes de dar la respuesta final. La API lo devuelve aparte, y aquí se analiza por separado. |
| **Jailbreak** | Mensaje pensado para que el modelo se salte sus propias normas (por ejemplo, haciéndole creer que está en un juego de rol). |
| **Inyección de instrucciones** (*prompt injection*) | Ataque en el que el texto del usuario intenta sustituir las instrucciones de la aplicación («olvida lo anterior y haz esto otro»). |
| **Guardrail / salvaguarda** | Filtro que se coloca delante o detrás del modelo para detectar y bloquear entradas o salidas peligrosas. Es el «portero» que se evalúa. |
| **Capa** | Cada salvaguarda dentro de una configuración. Una configuración puede tener varias capas en fila. |
| **Configuración (C0–C5)** | Combinación concreta de salvaguardas. C0 no tiene ninguna; C5 las tiene todas. |
| **Canaria** | Código inventado (por ejemplo `TFG-CANARIO-ZAFIRO-6821`) que se esconde en el mensaje de sistema. Si aparece en la respuesta, el ataque ha conseguido sacar información que debía quedar oculta. Es inofensivo: no es una contraseña real. |
| **Oráculo** | Regla que decide si un ataque tuvo éxito. El principal es buscar la canaria letra por letra en la respuesta. |
| **Juez** | Otro LLM (`openai/gpt-4.1-mini`) que lee la respuesta y opina si el ataque tuvo éxito. Es una medida secundaria y su fiabilidad se comprueba con etiquetas humanas. |
| **Etiqueta humana** | Valoración hecha por una persona sobre una respuesta, que sirve para medir cuánto acierta el juez. |
| **Control benigno** | Pregunta inocente (muchas veces con palabras que suenan peligrosas, como «¿cómo mato un proceso de Linux?») que sirve para ver si las salvaguardas bloquean de más. |
| **ASR** (tasa de éxito del ataque) | De cada 100 ataques, cuántos consiguen su objetivo. Cuanto más baja, mejor protegido. |
| **DSR** (tasa de éxito de la defensa) | De los ataques que funcionan sin protección (C0), qué proporción bloquea una configuración. Cuanto más alta, mejor. |
| **Falso positivo / FPR** | Bloquear algo que era inocente. La FPR es la proporción de controles benignos bloqueados. |
| **Sobre-rechazo** | El propio modelo se niega a contestar una pregunta inocente. |
| **Intervalo de Wilson** | Margen de error de una proporción. Con pocos casos el margen es grande, y por eso se publica siempre junto al resultado. |
| **Corpus** | Colección de casos (ataques y controles) que se envían al modelo. Están en `data/attacks/`. |
| **Corpus de desarrollo / de evaluación** | El de desarrollo sirve para poner a punto el banco y sus resultados ya se han visto. El de evaluación se prepara aparte y se congela antes de ejecutarlo, para que los resultados no estén influidos por haber ajustado nada. |
| **Manifiesto** | Fichero que acompaña a un corpus y apunta de dónde sale cada caso y su huella. |
| **Huella (SHA-256, hash)** | «Huella dactilar» de un fichero: un código que cambia si se modifica un solo carácter. Sirve para demostrar que un fichero no se ha tocado. |
| **Piloto** | Ejecución pequeña (de 1 a 20 casos) para comprobar que una pieza funciona. No mide eficacia. |
| **Ejecución / `run_id`** | Una pasada del banco con una configuración y un corpus. Cada ejecución tiene un nombre (`run_id`) y genera un fichero JSONL. |
| **Réplica** | Repetir el mismo caso para ver si el modelo responde siempre igual. |
| **OWASP LLM01, LLM05, LLM07** | Categorías de riesgo de una lista de referencia (OWASP Top 10 para aplicaciones con LLM): inyección de instrucciones, manejo inseguro de la salida y filtración del mensaje de sistema. |
| **Consumidor** | Programa que recibe la respuesta del modelo y hace algo con ella. Aquí es una simulación inofensiva que solo anota si habría aceptado una acción prohibida. |
| **OpenRouter** | Servicio de pago que da acceso a muchos LLM con una sola cuenta. El banco lo usa para hablar con todos los modelos. |
| **API** | Forma en que un programa pide algo a otro servicio por Internet. |
| **Adaptador** | Pieza de código que conecta el banco con una herramienta concreta (un modelo, una salvaguarda o el juez). |
| **JSON** | Formato de texto estructurado con pares «campo: valor», fácil de leer por un programa. |
| **JSONL** | Fichero con un objeto JSON por línea. Cada ejecución guarda así una línea de cabecera y una línea por caso. |
| **YAML** | Formato de texto sencillo para ficheros de configuración. Cada configuración C0–C5 es un YAML de `configs/`. |
| **Git / commit** | Git guarda el historial del proyecto. Un *commit* es una «foto» fechada de todos los ficheros; cada ejecución anota en qué commit se hizo. |
| **Repositorio** | La carpeta del proyecto con todo su historial de Git. |
| **Prueba automática (test)** | Pequeño programa que comprueba que otra parte del código hace lo que debe. Aquí no hacen llamadas de pago. |
| **mypy** | Herramienta que revisa que los tipos de datos del código sean coherentes. |
| **`--dry-run`** | Modo de ensayo: comprueba la configuración y el corpus y muestra el plan, sin llamar a ningún modelo. |
