export interface EventPayloads {
  'user.verify-email': { email: string; token: string, mode?: string };
  'user.password-reset': { email: string; token: string, mode?: string };
}