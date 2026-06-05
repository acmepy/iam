export class RbacError extends Error {
  constructor(message, status = 400, code = "RBAC_ERROR", errors = {}, stack) {
    super(message);

    this.name = this.constructor.name;
    this.status = status;
    this.code = code;
    this.errors = errors;
    this.isOperational = true;

    if (stack) {
      this.stack = stack;
    }

    Error.captureStackTrace?.(this, this.constructor);
  }
}

export class AuthRequiredError extends RbacError {
  constructor(message = "Usuario y clave son necesarios") {
    super(message, 401, "AUTH_REQUIRED");
  }
}

export class AuthError extends RbacError {
  constructor(message = "Credenciales inválidas") {
    super(message, 401, "AUTH_ERROR");
  }
}

export class TokenRequiredError extends RbacError {
  constructor(message = "Token requerido") {
    super(message, 401, "TOKEN_REQUIRED");
  }
}

export class TokenInvalidError extends RbacError {
  constructor(message = "Token inválido") {
    super(message, 401, "TOKEN_INVALID");
  }
}

export class SessionRequiredError extends RbacError {
  constructor(message = "Sesión requerida") {
    super(message, 401, "SESSION_REQUIRED");
  }
}

export class SessionInactiveError extends RbacError {
  constructor(message = "Sesión inactiva") {
    super(message, 401, "SESSION_INACTIVE");
  }
}

export class PermissionRequiredError extends RbacError {
  constructor(message = "Permiso requerido") {
    super(message, 403, "PERMISSION_REQUIRED");
  }
}

export class ForbiddenError extends RbacError {
  constructor(message = "No tiene permisos para realizar esta acción") {
    super(message, 403, "FORBIDDEN");
  }
}

export class NotFoundError extends RbacError {
  constructor(message = "Registro no encontrado") {
    super(message, 404, "NOT_FOUND");
  }
}

export class AdapterError extends RbacError {
  constructor(message = "Error en adapter", errors = {}) {
    super(message, 500, "ADAPTER_ERROR", errors);
  }
}

export class ValidationError extends RbacError {
  constructor(message = "Error de validación", errors = {}) {
    super(message, 400, "VALIDATION_ERROR", errors);
  }
}
