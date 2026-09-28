# Dependencias externas

- Las dependencias externas son la fuente de verdad de su API, sus tipos, sus nombres y sus convenciones.
- No crear aliases, adaptadores de compatibilidad ni conversiones de nombres para ajustar una dependencia al código del proyecto.
- Cuando una dependencia cambie o exponga una interfaz distinta, actualizar el código consumidor y sus pruebas para usar esa interfaz directamente.

## Documentación

Solo actualizar el README para documentar funcionalidades ya implementadas y verificadas.
No agregar ejemplos, opciones ni comportamiento futuro o no probado.

## Registro de tareas

- Registrar las tareas del proyecto en `taks.md` y mantener sus estados actualizados.
- Usar `[]` para tareas pendientes y `[X]` para tareas completadas.
- Marcar una tarea como completada solo después de implementarla y verificarla.
