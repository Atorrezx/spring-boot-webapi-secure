# 4. Análisis y conclusiones

El análisis se basa en los reportes de [`antes-584fd8d/`](antes-584fd8d/) y [`despues-df8e9e38/`](despues-df8e9e38/), correspondientes a los siguientes commits:

- **Antes:** `584fd8d9b9ce6d1ac4ef6d41cfbabc0f0f7ae3dc`.
- **Después:** `df8e9e38f0ca890be73748024e12b22173968264`.

Ambos fueron analizados en la [ejecución exitosa 37668111583 de GitHub Actions](https://github.com/Atorrezx/spring-boot-webapi-secure/actions/runs/37668111583), con herramientas Docker y controles compartidos. Se seleccionaron tres hallazgos relevantes: dos con correcciones observables y uno pendiente de evaluación contextual.

## 4.1. Inyección SQL en la búsqueda de productos

### Evidencia y componente afectado

El reporte anterior `antes-584fd8d/semgrep-results.json` registra tres detecciones relacionadas con SQL en `src/main/java/bo/edu/devsecops/controller/ProductController.java`:

- `controls.lab-java-sql-concatenation`, línea 24.
- `controls.java.spring.security.injection.tainted-sql-string.tainted-sql-string`, línea 24.
- `controls.java.spring.security.audit.spring-sqli.spring-sqli`, línea 25.

Son detecciones de un mismo problema, no tres vulnerabilidades independientes. El código original del método `search`, asociado a `GET /api/products/search`, construía la consulta incorporando directamente el parámetro `name`:

```java
String sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + name + "%'";
return jdbcTemplate.queryForList(sql);
```

### Riesgo para el proyecto

La entrada controlada por el usuario podía modificar la estructura de la consulta. Según los permisos de la cuenta de base de datos y el comportamiento del controlador JDBC, esto podría permitir acceso indebido a información u otras operaciones no previstas. No se ejecutó una prueba de explotación sobre la aplicación original.

### Acción aplicada y justificación

La versión corregida utiliza una consulta parametrizada:

```java
return jdbcTemplate.queryForList(
    "SELECT id, name, price FROM products WHERE name LIKE ?",
    "%" + name + "%");
```

El marcador `?` separa la instrucción SQL del valor suministrado por el usuario. La concatenación restante construye el valor de búsqueda, no la consulta. Los caracteres `%` y `_` pueden conservar su significado como comodines de `LIKE`; la parametrización impide que el valor se interprete como estructura SQL, pero no redefine la semántica de búsqueda.

### Comparación antes/después

| Evidencia | Antes | Después |
|---|---|---|
| Construcción de SQL | Entrada concatenada en la consulta | Consulta con parámetro enlazado |
| Detecciones SQL de Semgrep | 3 | 0 |

### Cómo comprobar la corrección

Se recomienda agregar una prueba de integración, en un entorno autorizado y con datos conocidos, que envíe valores como `' OR 1=1 --` y compruebe que no alteran la consulta ni permiten recuperar registros ajenos al criterio de búsqueda. También deben conservarse pruebas de búsquedas legítimas. La desaparición de las alertas respalda la corrección estructural, pero no sustituye estas pruebas.

## 4.2. Dependencia vulnerable: Apache Commons Text

### Evidencia y componente afectado

El reporte `antes-584fd8d/trivy-report.json` identifica `org.apache.commons:commons-text` versión **1.9**, incluida en el JAR de la aplicación, y la vulnerabilidad **CVE-2022-42889**, clasificada como **CRITICAL**, con **CVSS 9.8** y **CWE-94**. El reporte indica **1.10.0** como versión corregida.

La ubicación registrada incluye `springboot-devsecops-lab-1.0.0.jar/BOOT-INF/lib/commons-text-1.9.jar`. La vulnerabilidad aparece en dos ocurrencias del reporte; no deben interpretarse como dos vulnerabilidades distintas. El componente afectado es la dependencia empaquetada, declarada mediante Maven, no una vulnerabilidad demostrada en un método específico de la aplicación.

### Riesgo para el proyecto

Las versiones afectadas podían ejecutar código o realizar conexiones externas mediante determinados mecanismos de interpolación cuando procesaban entradas no confiables. Sin embargo, encontrar la biblioteca vulnerable **no demuestra que esa funcionalidad sea alcanzable desde esta aplicación**. El uso de `StringEscapeUtils`, por sí solo, no prueba exposición al mecanismo vulnerable de `StringSubstitutor`.

### Acción aplicada y justificación

Se actualizó Commons Text a **1.10.0**, versión presente en el inventario posterior. Esta actualización elimina la versión afectada y modifica los comportamientos predeterminados asociados a la vulnerabilidad. Se recomienda mantener la dependencia en una versión soportada y revisar periódicamente nuevos avisos de seguridad.

### Comparación antes/después

| Evidencia | Antes | Después |
|---|---|---|
| Versión empaquetada | 1.9 | 1.10.0 |
| Ocurrencias Trivy de CVE-2022-42889 | 2 | 0 |

### Cómo comprobar la corrección

Debe verificarse la versión efectivamente incluida en el JAR desplegable, no solamente la declarada en Maven, y repetir Dependency-Check y Trivy con controles equivalentes. Si la aplicación incorpora interpolación de cadenas, también corresponde revisar sus entradas y las funciones habilitadas.

## 4.3. Protección CSRF desactivada

### Evidencia y configuración afectada

La regla personalizada de Semgrep `controls.lab-csrf-disabled` aparece en ambos snapshots: línea 15 antes y línea 16 después de `src/main/java/bo/edu/devsecops/config/SecurityConfig.java`. La configuración conserva:

```java
.csrf(csrf -> csrf.disable())
```

La versión corregida también habilita HTTP Basic. El resultado tiene severidad `WARNING` y estado `NO_VALIDATOR`: identifica una configuración que requiere revisión, no una explotación demostrada.

### Riesgo para el proyecto

La desactivación de CSRF puede ser riesgosa cuando un navegador adjunta automáticamente credenciales —por ejemplo, cookies o credenciales Basic— a solicitudes que modifican el estado de la aplicación. La relevancia efectiva depende de los clientes, las operaciones expuestas y las restricciones sobre las solicitudes.

El comentario que describe la API como «sin estado» no demuestra que esa condición esté implementada. Además, una política sin sesiones no elimina por sí sola el riesgo si siguen existiendo credenciales enviadas automáticamente por el navegador.

### Acción propuesta y justificación

Primero debe definirse el modelo real de consumo y autenticación:

- Si existen operaciones protegidas utilizadas desde navegadores con credenciales automáticas, corresponde habilitar una protección CSRF adecuada.
- Si la API utiliza exclusivamente tokens bearer enviados explícitamente, debe documentarse y comprobarse ese modelo antes de justificar la desactivación.

No se recomienda cambiar la política sin evaluar primero ese contexto.

### Comparación antes/después

El hallazgo permanece: **una detección antes y una después**. No se considera corregido ni se afirma que sea explotable sin evaluar los clientes, las operaciones expuestas y sus restricciones.

### Cómo comprobar la corrección

En un entorno de pruebas, las operaciones que deban protegerse tendrían que rechazar solicitudes sin token CSRF válido y aceptar solicitudes legítimas con token. Para un diseño bearer-only, debe comprobarse que las operaciones protegidas no aceptan autenticación ambiental mediante cookies o Basic.

## 4.4. Conclusiones generales y limitaciones

| Scanner | Antes | Después | Unidad |
|---|---:|---:|---|
| Dependency-Check | 132 | 0 | Ocurrencias de vulnerabilidades; JSON nativo y resultados SARIF coincidentes |
| SpotBugs | 2 | 2 | Resultados SARIF, coincidentes con XML |
| Semgrep | 10 | 2 | Resultados JSON, sin errores del scanner |
| Trivy | 104 | 0 | Ocurrencias de vulnerabilidades de librerías Java |
| Conftest | 0 | 0 | Fallos y advertencias; siete controles exitosos en ambos |

Los resultados respaldan una reducción de las vulnerabilidades conocidas de dependencias y la eliminación de patrones inseguros, particularmente la construcción de SQL mediante concatenación. No obstante, deben considerarse los siguientes límites:

- **SpotBugs conserva dos resultados** y Semgrep mantiene las observaciones sobre CSRF y posible registro de datos sensibles. No se atribuye una corrección de SpotBugs a los cambios observados.
- Dependency-Check examinó **32 dependencias** en cada snapshot y utilizó NVD, con OSS Index desactivado en ambos. El cero posterior se limita a esa cobertura y a los datos utilizados.
- Trivy analizó el directorio compilado `target` mediante `rootfs`, limitado a librerías Java. Los inventarios contienen **101 y 125 entradas** respectivamente, incluyendo registros repetidos. Las rutas identifican el JAR compilado y JARs anidados en `BOOT-INF/lib`; algunas entradas carecen de `FilePath`, por lo que los artefactos no permiten excluir la contribución de otros archivos generados en `target`.
- Trivy **no analizó la imagen Docker ni sus paquetes del sistema operativo**. Su cero posterior no demuestra la corrección de `libpng` ni la seguridad de la imagen desplegada.
- Conftest aprobó **siete controles en ambos casos**. Esto verifica aspectos de la política Dockerfile, pero no demuestra que el Dockerfile original se pueda construir, que su healthcheck funcione o que la aplicación sea segura en ejecución.
- Los conteos son ocurrencias propias de cada herramienta. Trivy registra **52 combinaciones distintas de paquete, versión instalada e identificador de vulnerabilidad** dentro de sus 104 ocurrencias anteriores. Los resultados no deben sumarse entre scanners ni confundirse con hallazgos deduplicados por DefectDojo.
- Las bases y reglas corresponden a la ejecución del **7 de octubre de 2026**; no reproducen la fecha histórica de informes PDF anteriores. Los metadatos de caché coinciden entre snapshots, pero sus hashes no son checksums de las bases completas ni garantizan reproducibilidad binaria histórica.
- Un resultado de cero significa ausencia de detecciones dentro del alcance, los controles y la fecha del análisis, no ausencia absoluta de vulnerabilidades.

## 4.5. Recomendaciones priorizadas

1. **Evaluar la configuración CSRF según el uso real de la API.** Documentar clientes, mecanismos de autenticación y operaciones que modifican estado; comprobar la política elegida con pruebas negativas y positivas.
2. **Conservar las consultas parametrizadas mediante pruebas de regresión.** Cubrir entradas de inyección y búsquedas legítimas para evitar que futuras modificaciones reintroduzcan la concatenación SQL.
3. **Mantener el análisis periódico de dependencias y del artefacto empaquetado.** Verificar las versiones efectivas, actualizar las bases de vulnerabilidades y preservar los controles de seguridad del proyecto.
4. **Revisar los resultados que permanecen.** Evaluar el posible registro de datos sensibles y los dos resultados SpotBugs en su contexto antes de aceptarlos, corregirlos o justificar su descarte.

**Las pruebas dinámicas propuestas en esta sección todavía no fueron ejecutadas.** La comparación utiliza reportes nativos y evidencia de código; no implica una prueba de explotación ni una importación real en DefectDojo. La redacción de este documento no modifica la aplicación ni los reportes de entrada.
