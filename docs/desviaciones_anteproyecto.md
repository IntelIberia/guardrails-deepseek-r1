# Desviaciones respecto al anteproyecto

1. Modelo objetivo. Uso `deepseek/deepseek-r1-0528` servido por DeepInfra,
   porque el DeepSeek-R1 de enero de 2025 no tenía proveedores en OpenRouter el
   17-11-2026. Es una contingencia acordada con el tutor que no figura en el
   anteproyecto. Los resultados valen para la revisión 0528.
2. Juez. `openai/gpt-4.1-mini` en lugar del clasificador de HarmBench. En los
   ataques de extracción el oráculo principal es la aparición literal de la
   canaria, que es determinista; el clasificador de HarmBench está pensado para
   contenido dañino, no para detectar una cadena. Mantengo la revisión manual
   de una muestra aleatoria. Como el juez resultó poco fiable en la pista B, en
   el nivel 3 sus positivos se revisan además con el juez publicado por
   JailbreakBench.
3. C4 y C5. Siguen la definición del anteproyecto: C4 = C1 + C2 + C3 y
   C5 = C4 + Guardrails AI en la salida.
4. C2. NeMo usa raíles de entrada y de salida; el anteproyecto preveía solo
   entrada y heurísticas. Es una ampliación.
5. Corpus. Los corpus de desarrollo usan ataques propios con canarias
   sintéticas, mientras que el anteproyecto toma Shen et al. como fuente
   principal. Los corpus de evaluación vuelven a partir de Shen et al. y añaden
   otras fuentes públicas (ver los protocolos de evaluación).

Más detalle sobre cada punto en [criterios_estudio.md](criterios_estudio.md).
