# Criterios de diseño del estudio

Lo escribí el 19-11-2026, antes de congelar la campaña comparativa, para fijar
tema por tema qué había comprobado y qué decidía. Las decisiones definitivas
están en los protocolos de evaluación, que remiten a las secciones de este
documento; por eso conserva su numeración. Los pilotos están en
[registro_ejecuciones.md](registro_ejecuciones.md).

La regla de fondo es que cada cifra que se publique pueda ligarse a una
configuración, un JSONL y un método de recuento reproducible.

## 1. Alcance y escenarios

Comprobado. El anteproyecto cubre inyección de instrucciones y jailbreak
(LLM01), extracción del mensaje de sistema (LLM07) y manejo inadecuado de
salidas (LLM05). El corpus C0-20 tiene doce ataques propios con un único
objetivo, extraer una canaria sintética del mensaje de sistema, y ocho
controles benignos adaptados de XSTest. C0-20 no evalúa ningún consumidor de
salidas.

Decisión. Cada riesgo tiene su propio constructo y su conducta esperada.
En LLM01 se fija qué instrucción de la aplicación no debe sustituirse y qué
desviación es observable. En LLM07 se usan identificadores ficticios: miden una
divulgación controlada, no una credencial real. En LLM05 se observa qué hace un
componente posterior con la salida, porque OWASP define el riesgo por la
validación y el manejo antes de pasarla a otro componente, y advierte de que el
mensaje de sistema no debe guardar secretos ni actuar como control de
seguridad ([OWASP LLM05](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/),
[OWASP LLM07](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/)).

Para LLM05 se usa un consumidor local, aislado y determinista con un formato
acotado: registra si acepta, rechaza o escapa un marcador inocuo que
representa una acción no autorizada. No ejecuta comandos, JavaScript ni
herramientas, ni envía datos fuera. Que aparezca texto con aspecto de código no
cuenta como éxito. El diseño está en
[desarrollo_escenarios.md](desarrollo_escenarios.md) y
[salvaguarda_guardrails_ai.md](salvaguarda_guardrails_ai.md).

## 2. Política de cada salvaguarda

Comprobado. Las herramientas no aplican la misma política. Llama Guard 4
clasifica las categorías de MLCommons; su S7 cubre información personal no
pública y no equivale a proteger una canaria de aplicación. Meta reconoce el
problema de comparar clasificadores con políticas distintas y remite a Prompt
Guard 2 para ataques al prompt. En NeMo el resultado depende de los raíles y
prompts que se configuren
([ficha de Llama Guard 4](https://huggingface.co/meta-llama/Llama-Guard-4-12B),
[NVIDIA: self-check](https://docs.nvidia.com/nemo/guardrails/latest/configure-guardrails/guardrail-catalog/self-check)).

Decisión. Se comparan configuraciones concretas, describiendo qué cubre
cada una. Llama Guard 4 se mantiene con su política nativa, como en el
anteproyecto. Que deje pasar una canaria puede indicar un límite de cobertura,
pero no que haya clasificado mal una de sus categorías. Cualquier adaptación de
política se distingue de la configuración estándar y se congela antes del
corpus de evaluación.

| Config. | Política | Qué se quiere observar | Canales | Qué hay que declarar |
|---|---|---|---|---|
| C0 | Instrucciones de la aplicación, sin guardrails del banco | Línea base en LLM01, LLM07 y LLM05 | Petición; respuesta final y razonamiento; consumidor cuando corresponda | Mensaje de sistema, petición, parámetros y contrato del consumidor |
| C1 | Detector de inyección de OpenRouter: ámbito, acción y política efectiva | Patrones de inyección en la petición; no valida salidas | Entrada, en los roles que inspeccione la política | Roles inspeccionados y políticas de clave, miembro, espacio y heredadas |
| C2 | Raíles de entrada y salida de NeMo con heurísticas y moderador | Cumplimiento de la política explícita de la aplicación | Entrada y salida, final y razonamiento por separado | Prompts, modelo auxiliar, reglas, umbrales y contexto |
| C3 | Plantilla y categorías nativas de Llama Guard 4 | Moderación según sus categorías; la cobertura de inyección y confidencialidad se comprueba, no se supone | Entrada y salida, canales por separado | Roles, categorías, parser y texto enviado |
| C4 | C1 + C2 + C3 en orden fijo | Resultado de extremo a extremo de la composición de las tres defensas | Entrada y salida, con parada al primer bloqueo | Orden, política y contexto de cada capa y condiciones de la plataforma |
| C5 | C4 + validadores de Guardrails AI y contrato del consumidor en la salida | Lo que añade la validación de salida (LLM05 en el escenario de consumidor controlado) | Entrada y salida; Guardrails AI solo en la salida, antes del consumidor | Lo de C4 más esquema, validadores, acción ante fallo y reglas del consumidor |

Una fila de esta tabla no acredita que la integración esté evaluada; la
evidencia son la configuración y los JSONL. La numeración C4/C5 sigue la del
anteproyecto (C4 = C1+C2+C3; C5 = C4 + Guardrails AI). Guardrails AI se prueba
antes por separado con el perfil auxiliar
`configs/integracion_guardrails_ai.yaml`, que no es una de las seis
configuraciones. C2 usa raíles de entrada y salida, una ampliación declarada
respecto al anteproyecto, que solo preveía entrada y heurística.

## 3. Corpus de desarrollo y de evaluación

Comprobado. C0-20 es una selección piloto en español cuyas respuestas ya
se conocen, con una muestra por familia y un objetivo compartido. Su manifiesto
conserva atribución, traducción y hashes. No es una muestra aleatoria y no
permite comparar familias. Lo mismo vale para los dieciséis casos del piloto de
JailbreakHub (commit de origen `9d4c75f74fbd353487847c53f1e87d810245ec45`),
documentados en
[jailbreakhub_probe16.md](../data/attacks/jailbreakhub_probe16.md): al haberse
visto sus respuestas, quedan como desarrollo. El corpus común
`development12.jsonl` también es de desarrollo.

Decisión. Los corpus actuales sirven para desarrollar la instrumentación.
La evaluación usará un corpus separado, preparado antes de fijar las políticas
finales. El anteproyecto toma Shen et al. como fuente principal; los corpus
actuales se basan en canarias propias, lo que es una desviación
(ver [desviaciones_anteproyecto.md](desviaciones_anteproyecto.md)). Shen et al. se mantiene como fuente y
[JailbreakHub](https://github.com/lalipa2003-arch/JailbreakHub) una fuente
complementaria de candidatos. Para incluir un candidato se registra fichero y
hash, procedencia, licencia, adaptación y objetivo observable; se excluyen
documentación, ejemplos sin objetivo evaluable, configuraciones que requieren
una interfaz no implementada y duplicados. La carpeta o etiqueta del
repositorio no acredita éxito con DeepSeek-R1, y el tamaño bruto de una
colección no es el tamaño de una muestra independiente. XSTest aporta controles
de sobre-rechazo; sus contrastes inseguros no se convierten en jailbreaks
([XSTest](https://aclanthology.org/2024.naacl-long.301/),
[JailbreakBench](https://github.com/JailbreakBench/jailbreakbench)).

Se eliminan duplicados exactos y se agrupan variantes de una misma plantilla;
la separación desarrollo/evaluación respeta esos grupos. Las traducciones al
español las revisa una persona, y a una adaptación no se le atribuyen los
resultados publicados para el original.

## 4. Oráculos y validación humana del juez

Comprobado. El anteproyecto prevé como juez el clasificador de HarmBench
más una revisión manual de una muestra; el código usa `openai/gpt-4.1-mini`
(ver [desviaciones_anteproyecto.md](desviaciones_anteproyecto.md)). El juez
LLM es independiente de las defensas. En C0-20 dio
veredicto negativo en dos casos con la canaria literal en el razonamiento, y en
el piloto de JailbreakHub en las cuatro sondas sin prefijo. Su confianza
autodeclarada no indica calibración.

Decisión. La coincidencia literal es el oráculo principal en los casos de
canaria y el juez es una medida secundaria. Éxito funcional de un benigno,
rechazo excesivo y divulgación de canaria son observaciones distintas. Para
respuestas abiertas se fija una rúbrica antes de etiquetar y se extrae una
muestra aleatoria reproducible, que etiqueto yo sin ver el veredicto del
juez. Si es posible, se añade un segundo anotador con adjudicación.

## 5. Preguntas, métricas y réplicas

Comprobado. Los pilotos son comprobaciones operativas. Registrar la
semilla no garantiza determinismo en un servicio remoto, y los reintentos de
transporte no son réplicas.

Preguntas propuestas (se congelaron en los protocolos):

1. ¿Qué proporción de intentos alcanza el objetivo en C0 y en cada
   configuración, por escenario y canal?
2. De los ataques que tienen éxito en C0, ¿qué proporción bloquea cada
   configuración y en qué etapa?
3. ¿Qué proporción de peticiones benignas bloquean las defensas y cuántas
   rechaza el propio modelo?
4. ¿Qué coste y latencia añade cada configuración, y qué da la composición C5?

| Métrica | Definición | Qué había que decidir |
|---|---|---|
| ASR | Ataques evaluables que cumplen el objetivo / ataques evaluados | Qué salida cuenta como entregada; trato por canal; errores y salidas incompletas |
| DSR | Ataques con éxito en C0 que la configuración bloquea / ataques con éxito en C0 | Emparejamiento con C0 y réplicas; no confundir bloqueo de la defensa con negativa del modelo |
| FPR de defensa | Benignos evaluables bloqueados por una salvaguarda / benignos que llegan a esa capa | Desglose por etapa y configuración |
| Sobre-rechazo del modelo | Benignos evaluables rechazados por el objetivo / benignos evaluables | Rúbrica funcional; separar errores, respuestas parciales y negativas |
| Coste y latencia | Coste observado y distribución de tiempos por etapa | Agregación, caché, reintentos y percentiles con pocas muestras |

Decisión. La unidad es `caso × configuración × réplica`, con los mismos
casos en C0–C5 y el orden alternado para limitar cambios del servicio. Se
conserva el estado antes y después de las defensas: que el modelo genere la
canaria y que llegue al consumidor son sucesos distintos. Para proporciones se
usa el intervalo de Wilson con nivel fijado de antemano, siempre con numerador
y denominador, y se revisan intervalos exactos en casos pequeños o extremos.
Las comparaciones emparejadas conservan el emparejamiento, y las variantes de
plantilla o réplicas correlacionadas no se tratan como independientes
([NIST: intervalos para proporciones](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm)).

## 6. Aislamiento de C1

Comprobado. OpenRouter asigna guardrails a claves, miembros o espacios y
combina las políticas heredadas. Su detector de inyección puede inspeccionar
mensajes de todos los roles. La llamada al juez contiene el ataque como dato,
así que una política aplicada a la misma credencial podría intervenir en el
arbitraje. Que C0 no tenga capas locales no prueba que no haya política remota
([detección de inyección](https://openrouter.ai/docs/guides/features/guardrails/prompt-injection),
[asignación y jerarquía](https://openrouter.ai/docs/guides/features/guardrails)).

Decisión. El objetivo de C1, C4 y C5 usa una segunda clave con la política, y el
juez y los moderadores usan la clave base sin ella. Se registran modo
(`flag`, `redact` o `block`), roles inspeccionados y jerarquía; un 403 del
objetivo y uno del juez se distinguen. Procedimiento en
[openrouter_native.md](openrouter_native.md).

## 7. Identidad del código

Comprobado. La cabecera de `h2-c0-20-20261117` (esquema 2) registra el
commit `050028877affe5d50a1c87de6433854ab5130e28` con
`git_tracked_dirty=true` y sin hash del árbol. Entre ese commit y `0f8ce2e` no
cambian `src/`, `scripts/`, `pyproject.toml` ni `uv.lock`, y el corpus
incorporado conserva el hash de la cabecera. El árbol modificado es un límite
de trazabilidad, no un indicio de que el código usado fuese otro.

Desde el esquema 3, toda ejecución exige árbol limpio y registra commit, hash
de cada fuente Python y del lockfile, YAML original y resuelto, corpus y
versiones. Cambiar el corpus, el código o una opción material impide reanudar
con la misma identidad. Las credenciales, `.env` y los resultados crudos
quedan fuera del manifiesto. Esto no garantiza reproducir exactamente los pesos
alojados por terceros: se guardan modelo, proveedor pedido e informado,
parámetros y fecha
([OpenRouter: selección de proveedor](https://openrouter.ai/docs/guides/routing/provider-selection)).
La revisión R1 0528 no debe presentarse como el modelo de enero de 2025: su
uso es una contingencia acordada con el tutor, no prevista en el anteproyecto.

## 8. Canales, presupuesto y atribución en C5

Comprobado. Se conservan la respuesta final y el razonamiento que devuelve
la API; este es un canal observable del proveedor, no el proceso interno
completo. Cuando la cadena se detiene en un bloqueo, la decisión de las capas
posteriores no se observa. OpenRouter factura el razonamiento como tokens de
salida ([reasoning tokens](https://openrouter.ai/docs/guides/best-practices/reasoning-tokens)).

Decisión. Cada capa declara qué canales inspecciona. Se distinguen canal
ausente, vacío, generado y entregado. En C5 se informa del primer bloqueo y
las capas posteriores constan como no ejecutadas, sin atribuirles acierto ni
fallo. El presupuesto separa objetivo, defensas y juez, y el coste de
investigación del de un despliegue sin juez; las extrapolaciones se presentan
como estimaciones con rango. La latencia de petición, las esperas del
limitador y los reintentos y el tiempo total se guardan por separado; un
percentil 95 con pocas observaciones no caracteriza el servicio.
