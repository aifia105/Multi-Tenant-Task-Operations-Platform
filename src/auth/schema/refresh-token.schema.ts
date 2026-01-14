import { Schema, SchemaFactory } from '@nestjs/mongoose';

export type RefreshTokenDocument = RefreshToken & Document;

@Schema({ timestamps: true })
export class RefreshToken {
  _id: string;
  userId: string;
  token: string;
  expiresAt: Date;
}

export const RefreshTokenSchema = SchemaFactory.createForClass(RefreshToken);

RefreshTokenSchema.index(
  { userId: 1, token: 1 },
  { expireAfterSeconds: 60 * 60 * 24 * 7 },
);
