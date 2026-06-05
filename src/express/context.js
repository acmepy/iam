export const expressContext = Symbol("iam.expressContext");

export function setContext(req, context) {
  req[expressContext] = context;
}

export function getContext(req) {
  return req[expressContext];
}
