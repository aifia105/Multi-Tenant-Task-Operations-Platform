export const UserRole = {
  ADMIN: 'ADMIN',
  ORGANIZATIONMANAGER: 'ORGANIZATIONMANAGER',
  ORGANIZATIONMEMBER: 'ORGANIZATIONMEMBER',
} as const;

export type UserRoleType = (typeof UserRole)[keyof typeof UserRole];
