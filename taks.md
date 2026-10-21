# Tareas

Estados: [] pendiente, [X] completado.

- [X] Conservar el id del permiso en el include eager para evitar eliminar permisos distintos al deduplicar; test específico, 46 pruebas y build correctos.

- [X] Corregir la detección de endpoints para usar la ruta de la petición en lugar del punto de montaje del router; verificados los tests de cuentas con baseUrl /iam, la suite completa y el build.

- [X] Eliminar logging.test.js y verificar la suite restante, conservando las pruebas de integración de logging en Express; 46 pruebas correctas.

- [X] Corregir llamadas y pruebas para conservar el formato de log [IAM], operación, txId, mensaje y detalles; 49 pruebas y build correctos.

- [X] Simplificar normalizeLogging conservando niveles, valores por defecto y contexto del logger; verificado con 49 pruebas y build.

- [X] Agregar txId a los logs cuando exista en el contexto; verificado con pruebas de aislamiento concurrente y ausencia de contexto.
- [X] Mover getContext a las opciones de auth y verificar los logs de autenticación y autorización.

- [X] Establecer expiresIn JWT por defecto en 365 dias y verificar el vencimiento emitido.
- [X] Cerrar exclusivamente la sesion del token Bearer mediante POST /logout sin cuerpo; actualizar cliente y pruebas.

- [X] Implementar registro de usuarios, habilitado explícitamente, sin permitir asignar roles ni options desde el registro.
- [X] Implementar edición de los datos básicos del usuario autenticado, sin permitir modificar roles ni options.
- [X] Implementar cambio de contraseña con validación de la contraseña actual; mantener por ahora el mecanismo existente de contraseñas.
- [X] Mantener el correo no único en registro y edición; identificar por userId la cuenta para restablecer su contraseña.
- [X] Mantener options en login; la aplicación sigue siendo responsable de forzar empresa y otros datos desde la sesión.
- [X] Implementar emisión de credenciales de restablecimiento desde una función de servidor: temporales, vinculadas al userId y de un solo uso mediante persistencia; el llamador autoriza la recuperación.
- [X] Generar el enlace de restablecimiento con URL configurada por el servidor, sin enviar notificaciones.
- [X] Implementar restablecimiento de contraseña mediante credencial válida, consumirla e invalidar las sesiones existentes sin reactivar cuentas desactivadas.
- [X] Incorporar registro, perfil, cambio y restablecimiento al cliente de navegador y verificar su integración con el middleware.
- [] Integrar en la aplicación o en un proyecto externo el envío del link de restablecimiento, previa verificación de identidad; IAM no enviará correos, SMS ni WhatsApp.
