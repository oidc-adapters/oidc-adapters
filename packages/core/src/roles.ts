export interface RolesProvider {
  hasRole (role: string): boolean | Promise<boolean>

  getRoles (): string[] | Promise<string[]>
}
