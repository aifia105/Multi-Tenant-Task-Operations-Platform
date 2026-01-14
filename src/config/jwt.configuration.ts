import { registerAs } from '@nestjs/config';

export default registerAs('jwt', () => ({
  secret: process.env.JWT_SECRET,
  expiresIn: process.env.JWT_EXPIRES_IN,
  refreshSecret: process.env.JWT_REFRESH_SECRET || '15m',
  refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  refreshTokenMaxAge: 7 * 24 * 60 * 60 * 1000,
}));
