export interface PermissionsProvider {
  hasPermission (permission: string): boolean | Promise<boolean>

  hasResourcePermission (resource: string, permission?: string): boolean | Promise<boolean>

  getPermissions (): string[] | Promise<string[]>

  getResourcePermissions (resource: string): string[] | Promise<string[]>
}
