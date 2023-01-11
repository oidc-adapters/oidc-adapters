export interface RolesProvider {
  hasRole (role: string): boolean

  getRoles (): string[]
}

export interface RolesAsyncProvider {
  hasRole (role: string): Promise<boolean>

  getRoles (): Promise<string[]>
}
